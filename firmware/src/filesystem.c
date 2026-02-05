/**
 * @file filesystem.c
 * @author Samuel Meyers
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>

#include "filesystem.h"
#include "simple_flash.h"
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include "secrets.h"

#include <wolfssl/wolfcrypt/settings.h>


int load_fat() {
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat() {
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
}

/** @brief Initialize the filesystem
 *
 *
 * @return 0 upon success. A negative value on error.
*/
int init_fs() {
    return load_fat();
}

/** @brief Check whether a file is in use
 *
 *  @param slot The slot to check
 *
 * @return True if the slot is in use. False otherwise.
*/
bool is_slot_in_use(slot_t slot) {
    file_t temp_file;
    return (!read_file(slot, &temp_file) && temp_file.in_use == FILE_IN_USE);
}

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to check
 *
 * @return 0 upon success. A negative value otherwise.
*/

static int load_ecc_pub_from_pem(ecc_key* pub)
{
    int ret;
    word32 idx = 0;

    wc_ecc_init(pub);

    ret = wc_EccPublicKeyDecode((const byte*)ECC_PUBLIC_KEY_PEM,
                                &idx,
                                pub,
                                (word32)XSTRLEN(ECC_PUBLIC_KEY_PEM));
    return ret;
}

static int ecc_encrypt_blob(const uint8_t* pt, word32 ptLen,
                            uint8_t* ct, word32* ctLen,
                            ecc_key* recipient_pub)
{
    int ret;
    WC_RNG rng;
    ecc_key eph;   // ephemeral sender key (priv)

    wc_ecc_init(&eph);

    ret = wc_InitRng(&rng);
    if (ret != 0) { wc_ecc_free(&eph); return ret; }

    // Make ephemeral P-256 key. (32 bytes => P-256)
    ret = wc_ecc_make_key(&rng, 32, &eph);
    if (ret != 0) { wc_FreeRng(&rng); wc_ecc_free(&eph); return ret; }

    // LENGTH_ONLY_E sizing pass (works in many wolfCrypt APIs)
    ret = wc_ecc_encrypt(&eph, recipient_pub, pt, ptLen, NULL, ctLen, NULL);
    if (ret != LENGTH_ONLY_E && ret != 0) {
        wc_FreeRng(&rng);
        wc_ecc_free(&eph);
        return ret;
    }

    ret = wc_ecc_encrypt(&eph, recipient_pub, pt, ptLen, ct, ctLen, NULL);

    wc_FreeRng(&rng);
    wc_ecc_free(&eph);
    return ret;
}

int create_file_encrypted(
    file_t* dest,
    group_id_t group_id,
    char* name,
    uint16_t contents_len,
    uint8_t* contents_plain
){
    int ret;
    ecc_key pub;
    WC_RNG rng;

    // uint8_t enc_buf[FILE_MAX_CONTENTS];   // whatever max dest->contents is
    // word32 enc_len = sizeof(enc_buf);

    uint8_t enc_buf[sizeof(((file_t*)0)->contents)];
    word32 enc_len = (word32)sizeof(enc_buf);


    ret = wc_InitRng(&rng);
    if (ret != 0) return ret;

    ret = load_ecc_pub_from_pem(&pub);
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    ret = ecc_encrypt_blob(contents_plain, contents_len, enc_buf, &enc_len, &pub);
    wc_ecc_free(&pub);
    wc_FreeRng(&rng);
    if (ret != 0) return ret;

    // now store ciphertext in file object
    return create_file(dest, group_id, name, (uint16_t)enc_len, enc_buf);
}

int create_file(
    file_t *dest,
    group_id_t group_id,
    char *name,
    uint16_t contents_len,
    uint8_t *contents
) {
    memset(dest, 0, sizeof(file_t));

    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id;
    dest->contents_len = contents_len;

    // name must be null terminated, and the contents are defined by a length
    strcpy(dest->name, name);
    memcpy(dest->contents, contents, contents_len);

    return 0;
}

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to write the file to
 *  @param src The sourc file to store
 *  @param uuid The UUID to store in the FAT
 *
 * @return 0 upon success. A negative value otherwise.
*/
int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
    unsigned int length, flash_addr;

    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->contents_len);
    // Update the FAT for the new file
    memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    store_fat();

    // erase the pages that will store the file
    for (int i = 0; i < FILE_PAGE_COUNT; i++) {
        flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
    }

    // now write the file
    return flash_simple_write(FILE_ALLOCATION_TABLE[slot].flash_addr, src, length);
}

/** @brief Read a file from persistent storage into memory
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *
 * @return 0 upon success. A negative value otherwise.
*/
int read_file(slot_t slot, file_t *dest) {
    int flash_addr, file_size;

    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;
    if (flash_addr < 0 || file_size < 0) {
        return -1;
    }
    flash_simple_read(flash_addr, dest, file_size);

    return 0;
}

/** @brief Get a read-only pointer to a file's metadata
 *
 *  @param slot The slot to get metadata for
 *
 * @return A filesystem_entry_t * on success. NULL on error.
*/
const filesystem_entry_t *get_file_metadata(slot_t slot) {
    return &FILE_ALLOCATION_TABLE[slot];
}
