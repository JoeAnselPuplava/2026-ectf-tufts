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
#include <stdio.h> 
#include <stdlib.h>

#include "filesystem.h"
#include "simple_flash.h"
#include "secrets.h"
#include "security.h"
#include "host_messaging.h"
#include "board_random.h"

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>

// Helper buffer for debug formatting
static char dbg_buf[128];

int load_fat() {
    // print_debug("Loading FAT from flash...");
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    // print_debug("FAT Loaded.");
    return 0;
}
extern void DL_Common_delayCycles(uint32_t cycles); 

int store_fat() {
    // print_debug("FAT: Starting Erase...");
    
    // Force a massive delay to guarantee the UART buffer pushes the text out
    // DL_Common_delayCycles(32000000); // roughly 1 second at 32MHz
    
    flash_simple_erase_page((uint32_t)_FLASH_FAT_START);

    // print_debug("FAT: Erase survived. Starting Write...");
    // DL_Common_delayCycles(32000000); 
    
    int ret = flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    
    // print_debug("FAT: Write survived!");
    return ret;
}

int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
    unsigned int length, flash_addr;

    sprintf(dbg_buf, "write_file: Writing slot %d", slot);
    print_debug(dbg_buf);

    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->contents_len);
    
    sprintf(dbg_buf, "FILE: Target Addr: 0x%08X, Pages: %d", flash_addr, FILE_PAGE_COUNT);
    print_debug(dbg_buf);
    
    // Update FAT
    memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    
    // 1. Store FAT (This function handles its own interrupts)
    store_fat();

    // 2. Erase File Pages safely
    print_debug("FILE: Starting Erase loop...");
    
    // --- SHIELD UP ---
    __disable_irq();
    for (int i = 0; i < FILE_PAGE_COUNT; i++) {
        flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
    }
    __enable_irq(); 
    // --- SHIELD DOWN ---

    print_debug("FILE: Erase survived. Starting Write...");
    
    // 3. Write File safely
    // --- SHIELD UP ---
    __disable_irq();
    int ret = flash_simple_write(flash_addr, src, length);
    __enable_irq();
    // --- SHIELD DOWN ---
    
    print_debug("FILE: Write survived!");
    return ret;
}

int init_fs() {
    print_debug("Initializing Filesystem...");
    return load_fat();
}

bool is_slot_in_use(slot_t slot) {
    uint32_t in_use_flag = 0;
    int flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;

    // If the FAT points to invalid memory, it's not in use
    if (flash_addr <= 0 || flash_addr == 0xFFFFFFFF) {
        return false;
    }

    // Read ONLY the first 4 bytes (the in_use flag) straight from flash
    flash_simple_read(flash_addr, &in_use_flag, sizeof(in_use_flag));

    return (in_use_flag == FILE_IN_USE);
}

// ============================================================================
// RSA + AES-CBC File Encryption - Ultra Compatible Version
// ============================================================================

#define AES_KEY_LEN 32      
#define ECC_BLOB_RESERVED_SIZE 128

// For CBC mode
#define AES_IV_LEN 16

#ifndef WC_MGF1SHA256
    #define WC_MGF1SHA256 26
#endif

/* ========================= Crypto constants ========================= */

// Total Header = [Encrypted AES Key Blob (128)] + [IV (16)]
#define TOTAL_HEADER_LEN (ECC_BLOB_RESERVED_SIZE + AES_IV_LEN)

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

    print_debug("  > AES Encrypt Direct: Start");
    if (!key || !iv || !in || !out || len == 0) return BAD_FUNC_ARG;
    if (len % AES_BLOCK_SIZE) return BAD_FUNC_ARG;

    ret = wc_AesSetKey(&ctx, key, AES_KEY_LEN, NULL, AES_ENCRYPTION);
    if (ret != 0) {
        sprintf(dbg_buf, "  > AES SetKey failed: %d", ret);
        print_debug(dbg_buf);
        return ret;
    }

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
    print_debug("  > AES Encrypt Direct: Success");
    return 0;
}

static int aes_cbc_decrypt_direct(const uint8_t* key, const uint8_t* iv,
                                  const uint8_t* in, uint8_t* out, word32 len)
{
    Aes ctx;
    int ret;

    print_debug("  > AES Decrypt Direct: Start");

    if (!key || !iv || !in || !out || len == 0) return BAD_FUNC_ARG;
    if (len % AES_BLOCK_SIZE) {
        print_debug("  > AES Decrypt Error: Bad block alignment");
        return BAD_FUNC_ARG;
    }

    ret = wc_AesSetKey(&ctx, key, AES_KEY_LEN, NULL, AES_DECRYPTION);
    if (ret != 0) {
        sprintf(dbg_buf, "  > AES SetKey failed: %d", ret);
        print_debug(dbg_buf);
        return ret;
    }

    uint8_t prev[AES_BLOCK_SIZE];
    memcpy(prev, iv, AES_BLOCK_SIZE);

    for (word32 i = 0; i < len; i += AES_BLOCK_SIZE) {
        uint8_t plain_block[AES_BLOCK_SIZE];

        ret = wc_AesDecryptDirect(&ctx, plain_block, in + i);
        if (ret != 0) return ret;

        for (word32 j = 0; j < AES_BLOCK_SIZE; j++) {
            out[i + j] = plain_block[j] ^ prev[j];
        }

        memcpy(prev, in + i, AES_BLOCK_SIZE);
    }

    print_debug("  > AES Decrypt Direct: Success");
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
    static WC_RNG rng __attribute__((aligned(8)));
    int ret;

    sprintf(dbg_buf, "create_file: Creating file '%s' for Group ID 0x%04X", name, group_id);
    print_debug(dbg_buf);

    /* 1. Validate Arguments */
    if (!dest || !name || (!contents_plain && contents_len != 0)) {
        print_debug("create_file: Bad Arguments");
        return BAD_FUNC_ARG;
    }

    memset(dest, 0, sizeof(file_t));
    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id; 
    strncpy(dest->name, name, MAX_NAME_SIZE - 1);
    dest->name[MAX_NAME_SIZE - 1] = '\0';

    if (contents_len > MAX_CONTENTS_SIZE) {
        print_debug("create_file: Buffer Overflow Error");
        return BUFFER_E;
    }

    /* 2. Generate Random AES Key and IV */
    print_debug("create_file: Generating random AES key and IV");
    
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        sprintf(dbg_buf, "create_file: wc_InitRng failed %d", ret);
        print_debug(dbg_buf);
        return ret;
    }

    uint8_t aes_key[AES_KEY_LEN];
    uint8_t iv[AES_IV_LEN];

    ret = wc_RNG_GenerateBlock(&rng, aes_key, sizeof(aes_key));
    if (ret != 0) {
        print_debug("create_file: RNG Gen Key failed");
        wc_FreeRng(&rng); 
        return ret;
    }

    ret = wc_RNG_GenerateBlock(&rng, iv, sizeof(iv));
    if (ret != 0) {
        print_debug("create_file: RNG Gen IV failed");
        wc_FreeRng(&rng); 
        return ret;
    }

    wc_FreeRng(&rng);

    /* 3. Encrypt AES Key using Group's Public Write Key */
    print_debug("create_file: Encrypting AES Key with Group Public Key...");
    
    uint8_t encrypted_key_blob[ECC_BLOB_RESERVED_SIZE]; 
    uint32_t blob_actual_len = sizeof(encrypted_key_blob);
    
    print_debug("ECIES Encryption of the Random AES Key");
    ret = encrypt_data(group_id, aes_key, AES_KEY_LEN, encrypted_key_blob, &blob_actual_len);
    
    if (ret != 0) {
        sprintf(dbg_buf, "create_file: encrypt_data failed with error %d", ret);
        print_debug(dbg_buf);
        secure_zero(aes_key, sizeof(aes_key));
        return ret;
    }
    
    sprintf(dbg_buf, "create_file: Key Encrypted. Blob size: %d bytes", (int)blob_actual_len);
    print_debug(dbg_buf);

    if (blob_actual_len > ECC_BLOB_RESERVED_SIZE) {
        print_debug("create_file: ECC Blob too large for header!");
        secure_zero(aes_key, sizeof(aes_key));
        return BUFFER_E;
    }

    /* 4 & 5. Check Capacity and Calculate Padding */
    print_debug("create_file: Padding plaintext content directly in buffer...");
    
    uint32_t pad_val = AES_BLOCK_SIZE - (contents_len % AES_BLOCK_SIZE);
    uint32_t padded_len = contents_len + pad_val;
    const uint32_t overhead = ECC_BLOB_RESERVED_SIZE + AES_IV_LEN;

    if (overhead + padded_len > sizeof(dest->contents)) {
        print_debug("create_file: Total file size exceeds storage capacity");
        secure_zero(aes_key, sizeof(aes_key));
        return BUFFER_E;
    }

    /* 6. Write Header and Encrypt In-Place */
    print_debug("create_file: Writing Header and Encrypting Body...");
    uint8_t* p = dest->contents;

    memset(p, 0, ECC_BLOB_RESERVED_SIZE);
    memcpy(p, encrypted_key_blob, blob_actual_len);
    p += ECC_BLOB_RESERVED_SIZE;

    memcpy(p, iv, AES_IV_LEN);
    p += AES_IV_LEN;

    // Zero-RAM in-place encryption
    memcpy(p, contents_plain, contents_len);
    for (uint32_t i = 0; i < pad_val; i++) {
        p[contents_len + i] = (uint8_t)pad_val;
    }

    ret = aes_cbc_encrypt_direct(aes_key, iv, p, p, padded_len);

    /* 7. Cleanup Sensitive Data */
    secure_zero(aes_key, sizeof(aes_key));

    if (ret != 0) {
        print_debug("create_file: Body encryption failed");
        return ret;
    }

    dest->contents_len = (uint16_t)(overhead + padded_len);
    
    print_debug("create_file: File creation successful.");
    return 0;
}

int decrypt_file_contents(
    const file_t* src,
    group_id_t group_id,
    const char* name,
    uint8_t* out_plain,
    uint16_t* out_plain_len
) {
    (void)name;
    int ret;

    sprintf(dbg_buf, "decrypt_file: Decrypting file for Group ID 0x%04X", group_id);
    print_debug(dbg_buf);

    if (!src || !out_plain || !out_plain_len) {
        return BAD_FUNC_ARG;
    }

    if (src->contents_len < TOTAL_HEADER_LEN) {
        print_debug("decrypt_file: File too short to contain header");
        return BUFFER_E;
    }

    /* Pointers into the file buffer */
    const uint8_t* key_blob = src->contents;
    const uint8_t* iv = src->contents + ECC_BLOB_RESERVED_SIZE;
    const uint8_t* ciphertext = src->contents + TOTAL_HEADER_LEN;
    const word32 ciphertext_len = (word32)src->contents_len - TOTAL_HEADER_LEN;

    sprintf(dbg_buf, "decrypt_file: Ciphertext length: %d", (int)ciphertext_len);
    print_debug(dbg_buf);

    if (ciphertext_len == 0 || (ciphertext_len % AES_BLOCK_SIZE) != 0) {
        print_debug("decrypt_file: Invalid ciphertext length (not block aligned)");
        return BAD_FUNC_ARG;
    }

    /* 1. Decrypt the AES Key Blob using Group Private Key */
    print_debug("decrypt_file: Recovering AES Key from ECC Blob...");
    
    uint8_t decrypted_aes_key[AES_KEY_LEN];
    uint32_t decrypted_key_len = sizeof(decrypted_aes_key);

    // THE FIX: Only pass the true size of the ECIES blob (113 bytes)
    // 65 (PubKey) + 16 (IV) + 32 (Ciphertext) = 113
    uint32_t actual_blob_size = 65 + AES_IV_SIZE + AES_KEY_LEN; 

    ret = decrypt_data(group_id, key_blob, actual_blob_size, decrypted_aes_key, &decrypted_key_len);

    if (ret != 0) {
        sprintf(dbg_buf, "decrypt_file: Failed to decrypt AES key (Error %d).", ret);
        print_debug(dbg_buf);
        return ret;
    }

    if (decrypted_key_len != AES_KEY_LEN) {
        sprintf(dbg_buf, "decrypt_file: Decrypted key wrong size (%d expected %d)", (int)decrypted_key_len, AES_KEY_LEN);
        print_debug(dbg_buf);
        secure_zero(decrypted_aes_key, sizeof(decrypted_aes_key));
        return -1;
    }

    print_debug("decrypt_file: AES Key recovered. Decrypting body...");

    /* 2. Decrypt the Body directly into 'out_plain' */
    if (*out_plain_len < ciphertext_len) {
        print_debug("decrypt_file: Output buffer too small");
        secure_zero(decrypted_aes_key, sizeof(decrypted_aes_key));
        return BUFFER_E;
    }

    ret = aes_cbc_decrypt_direct(decrypted_aes_key, iv, ciphertext, out_plain, ciphertext_len);
    secure_zero(decrypted_aes_key, sizeof(decrypted_aes_key));

    if (ret != 0) {
        print_debug("decrypt_file: Body decryption failed");
        return ret;
    }
    
    /* 3. Remove Padding in-place */
    print_debug("decrypt_file: Removing Padding...");
    word32 actual_len = 0;
    
    ret = remove_pkcs7_padding(out_plain, ciphertext_len, &actual_len);
    print_debug("out_plan");
    print_debug((char *)out_plain);
    if (ret != 0) {
        print_debug("decrypt_file: Padding check failed");
        secure_zero(out_plain, ciphertext_len); 
        return ret;
    }

    /* 4. Copy to Output */
    *out_plain_len = (uint16_t)actual_len;
    secure_zero(out_plain + actual_len, ciphertext_len - actual_len);
    
    sprintf(dbg_buf, "decrypt_file: Success. Size: %d", (int)actual_len);
    print_debug(dbg_buf);
    return 0;
}

// int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
//     unsigned int length, flash_addr;

//     sprintf(dbg_buf, "write_file: Writing slot %d", slot);
//     print_debug(dbg_buf);

//     flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
//     length = FILE_TOTAL_SIZE(src->contents_len);
    
//     // Update the FAT for the new file
//     memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
//     FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
//     FILE_ALLOCATION_TABLE[slot].length = length;
    
//     // store_fat() handles its own interrupts
//     store_fat();

//     // 1. Disable interrupts for the main file write!
//     __disable_irq();

//     // Erase the pages that will store the file
//     for (int i = 0; i < FILE_PAGE_COUNT; i++) {
//         flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
//     }

//     // Now write the file
//     int ret = flash_simple_write(FILE_ALLOCATION_TABLE[slot].flash_addr, src, length);
    
//     // 2. Re-enable interrupts
//     __enable_irq();

//     return ret;
// }

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

const filesystem_entry_t *get_file_metadata(slot_t slot) {
    return &FILE_ALLOCATION_TABLE[slot];
}