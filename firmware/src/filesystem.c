/**
 * @file filesystem.c
 * @author Samuel Meyers (Ultra-compatible version)
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * This version uses ONLY the most basic WolfSSL functions available in all builds
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>

#include "filesystem.h"
#include "simple_flash.h"
#include "secrets.h"
#include "host_messaging.h"
#include "random.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>

int load_fat() {
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

int store_fat() {
    flash_simple_erase_page(_FLASH_FAT_START);
    return flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
}

int init_fs() {
    return load_fat();
}

bool is_slot_in_use(slot_t slot) {
    file_t temp_file;
    return (!read_file(slot, &temp_file) && temp_file.in_use == FILE_IN_USE);
}

// ============================================================================
// RSA + AES-CBC File Encryption - Ultra Compatible Version
// ============================================================================

#define AES_KEY_LEN 32      
#define AES_BLOCK_SIZE 16   

// For CBC mode
#define AES_IV_LEN 16

#ifndef WC_MGF1SHA256
    #define WC_MGF1SHA256 26
#endif

/* ========================= Utilities ========================= */

void secure_zero(void* v, size_t n)
{
    volatile uint32_t* p32 = (volatile uint32_t*)v;

    // wipe 32-bit chunks
    while (n >= sizeof(uint32_t)) {
        *p32++ = 0;
        n -= sizeof(uint32_t);
    }

    // wipe remaining bytes
    volatile uint8_t* p8 = (volatile uint8_t*)p32;
    while (n--) {
        *p8++ = 0;
    }
}
/* ========================= Crypto constants ========================= */

#define PLAINTEXT_KEY_HDR_LEN (AES_KEY_LEN + AES_IV_LEN) /* key + iv */

/* ========================= PKCS#7 padding ========================= */

static word32 add_pkcs7_padding(uint8_t* data, word32 data_len, word32 block_size)
{
    word32 padding_len = block_size - (data_len % block_size);
    uint8_t padding_byte = (uint8_t)padding_len;

    for (word32 i = 0; i < padding_len; i++) {
        data[data_len + i] = padding_byte;
    }
    return data_len + padding_len;
}

static int remove_pkcs7_padding(const uint8_t* data, word32 data_len, word32* out_len)
{
    if (data_len == 0 || (data_len % AES_BLOCK_SIZE) != 0) {
        return BAD_FUNC_ARG;
    }

    uint8_t padding_len = data[data_len - 1];
    if (padding_len == 0 || padding_len > AES_BLOCK_SIZE) {
        return BAD_PADDING_E;
    }

    for (word32 i = 0; i < padding_len; i++) {
        if (data[data_len - 1 - i] != padding_len) {
            return BAD_PADDING_E;
        }
    }

    *out_len = data_len - padding_len;
    return 0;
}

/* ========================= AES-CBC (direct) ========================= */

static int aes_cbc_encrypt_direct(const uint8_t* key, const uint8_t* iv,
                                  const uint8_t* in, uint8_t* out, word32 len)
{
    Aes ctx;
    int ret;

    if (!key || !iv || !in || !out || len == 0) return BAD_FUNC_ARG;
    if (len % AES_BLOCK_SIZE) return BAD_FUNC_ARG;

    ret = wc_AesSetKey(&ctx, key, AES_KEY_LEN, NULL, AES_ENCRYPTION);
    if (ret != 0) return ret;

    uint8_t prev[AES_BLOCK_SIZE];
    memcpy(prev, iv, AES_BLOCK_SIZE);

    for (word32 i = 0; i < len; i += AES_BLOCK_SIZE) {
        uint8_t block[AES_BLOCK_SIZE];

        for (word32 j = 0; j < AES_BLOCK_SIZE; j++) {
            block[j] = in[i + j] ^ prev[j];
        }

        ret = wc_AesEncryptDirect(&ctx, out + i, block);
        if (ret != 0) return ret;

        memcpy(prev, out + i, AES_BLOCK_SIZE);
    }

    return 0;
}

static int aes_cbc_decrypt_direct(const uint8_t* key, const uint8_t* iv,
                                  const uint8_t* in, uint8_t* out, word32 len)
{
    Aes ctx;
    int ret;

    if (!key || !iv || !in || !out || len == 0) return BAD_FUNC_ARG;
    if (len % AES_BLOCK_SIZE) return BAD_FUNC_ARG;

    ret = wc_AesSetKey(&ctx, key, AES_KEY_LEN, NULL, AES_DECRYPTION);
    if (ret != 0) return ret;

    uint8_t prev[AES_BLOCK_SIZE];
    memcpy(prev, iv, AES_BLOCK_SIZE);

    for (word32 i = 0; i < len; i += AES_BLOCK_SIZE) {
        uint8_t plain_block[AES_BLOCK_SIZE];

        print_debug("Decrypting block");

        ret = wc_AesDecryptDirect(&ctx, plain_block, in + i);
        if (ret != 0) return ret;

        print_debug("Decrypted block");

        for (word32 j = 0; j < AES_BLOCK_SIZE; j++) {
            out[i + j] = plain_block[j] ^ prev[j];
        }

        memcpy(prev, in + i, AES_BLOCK_SIZE);
    }

    return 0;
}

/* ========================= Public API ========================= */

int create_file(
    file_t *dest,
    group_id_t group_id,
    char *name,
    uint16_t contents_len,
    uint8_t *contents_plain
) {
    int ret;
    WC_RNG rng;

    if (!dest || !name || (!contents_plain && contents_len != 0)) {
        return BAD_FUNC_ARG;
    }
    // print_debug("Creating file: group_id=%u, name=%s, contents_len=%u", group_id, name, contents_len);

    memset(dest, 0, sizeof(file_t));
    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id;
    strncpy(dest->name, name, MAX_NAME_SIZE - 1);
    dest->name[MAX_NAME_SIZE - 1] = '\0';

    if (contents_len > MAX_CONTENTS_SIZE) {
        return BUFFER_E;
    }

    /* Generate random AES key + IV */
    print_debug("Generating random AES key and IV");
    uint8_t aes_key[AES_KEY_LEN];
    uint8_t iv[AES_IV_LEN];

    print_debug("RNG: init...");
    ret = mspm0_trng_seed(aes_key, sizeof(aes_key));
    if (ret != 0) return ret;

    ret = mspm0_trng_seed(iv, sizeof(iv));
    if (ret != 0) return ret;

    char dbg[80];
    snprintf(dbg, sizeof(dbg), "k0=%08lx k1=%08lx",
            (unsigned long)(*(uint32_t*)&aes_key[0]),
            (unsigned long)(*(uint32_t*)&aes_key[4]));
    print_debug(dbg);

    print_debug("AES key and IV generated successfully");


    /* Pad plaintext */
    uint8_t padded_plain[MAX_CONTENTS_SIZE];
    memcpy(padded_plain, contents_plain, contents_len);
    word32 padded_len = add_pkcs7_padding(padded_plain, contents_len, AES_BLOCK_SIZE);

    /* Layout: [aes_key][iv][ciphertext] */
    const uint32_t overhead = PLAINTEXT_KEY_HDR_LEN;

    if (overhead + padded_len > sizeof(dest->contents)) {
        secure_zero(aes_key, sizeof(aes_key));
        secure_zero(padded_plain, sizeof(padded_plain));
        return BUFFER_E;
    }

    uint8_t* p = dest->contents;

    print_debug("Storing AES key and IV in file header");

    /* Store AES key (plaintext) */
    memcpy(p, aes_key, AES_KEY_LEN);
    p += AES_KEY_LEN;

    /* Store IV */
    memcpy(p, iv, AES_IV_LEN);
    p += AES_IV_LEN;

    /* Encrypt into remaining space */
    ret = aes_cbc_encrypt_direct(aes_key, iv, padded_plain, p, padded_len);

    /* Note: we must not zeroize aes_key before encryption completes */
    secure_zero(aes_key, sizeof(aes_key));
    secure_zero(padded_plain, sizeof(padded_plain));

    if (ret != 0) return ret;

    dest->contents_len = (uint16_t)(overhead + padded_len);
    return 0;
}

int decrypt_file_contents(
    const file_t* src,
    group_id_t group_id,
    const char* name,
    uint8_t* out_plain,
    uint16_t* out_plain_len
) {
    (void)group_id;
    (void)name;

    if (!src || !out_plain || !out_plain_len) {
        return BAD_FUNC_ARG;
    }

    if (src->contents_len < PLAINTEXT_KEY_HDR_LEN) {
        return BUFFER_E;
    }

    const uint8_t* aes_key = src->contents;
    const uint8_t* iv = src->contents + AES_KEY_LEN;
    const uint8_t* ciphertext = src->contents + PLAINTEXT_KEY_HDR_LEN;
    const word32 ciphertext_len = (word32)src->contents_len - PLAINTEXT_KEY_HDR_LEN;

    if (ciphertext_len == 0 || (ciphertext_len % AES_BLOCK_SIZE) != 0) {
        return BAD_FUNC_ARG;
    }

    if (*out_plain_len < ciphertext_len) {
        return BUFFER_E;
    }

    uint8_t padded_plain[MAX_CONTENTS_SIZE];
    if (ciphertext_len > MAX_CONTENTS_SIZE) {
        return BUFFER_E;
    }

    print_debug("Starting AES Decrypt");
    int ret = aes_cbc_decrypt_direct(aes_key, iv, ciphertext, padded_plain, ciphertext_len);
    if (ret != 0) {
        secure_zero(padded_plain, sizeof(padded_plain));
        return ret;
    }
    print_debug("Finished AES decrypt");
    
    print_debug("Removing PKCS#7 padding");
    word32 actual_len = 0;
    ret = remove_pkcs7_padding(padded_plain, ciphertext_len, &actual_len);
    if (ret != 0) {
        secure_zero(padded_plain, sizeof(padded_plain));
        return ret;
    }

    print_debug("Copying plaintext to output buffer");
    char dbg[32];
    sprintf(dbg, "Actual length: %lu", (unsigned long)actual_len);
    print_debug(dbg);
    memcpy(out_plain, padded_plain, actual_len);
    *out_plain_len = (uint16_t)actual_len;
    print_debug("Copied plaintext to output buffer");

    sprintf(dbg, "Padded plain length: %lu", (unsigned long)sizeof(padded_plain));
    print_debug(dbg);
    secure_zero(padded_plain, ciphertext_len);   // only wipe the bytes we touched
    print_debug("Returning 0");
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
