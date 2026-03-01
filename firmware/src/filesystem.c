/**
 * @file filesystem.c
 * @author Ming Dynasty
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
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

extern void DL_Common_delayCycles(uint32_t cycles); 

#define AES_KEY_LEN 32      
#define ECC_BLOB_RESERVED_SIZE 128

// For CBC mode
#define AES_IV_LEN 16

#ifndef WC_MGF1SHA256
    #define WC_MGF1SHA256 26
#endif

// Total Header = [Encrypted AES Key Blob (128)] + [IV (16)]
#define TOTAL_HEADER_LEN (ECC_BLOB_RESERVED_SIZE + AES_IV_LEN)

/**
 * @brief Loads the File Allocation Table (FAT) from flash memory.
 * * @return 0 upon successful read.
 */
int load_fat() {
    flash_simple_read((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    return 0;
}

/**
 * @brief Saves the current File Allocation Table (FAT) to flash memory.
 * * Safely disables interrupts to prevent hardware faults during the 
 * flash page erase and write operations.
 * * @return 0 upon success. A negative value on flash write failure.
 */
int store_fat() {

    __disable_irq();
    
    flash_simple_erase_page((uint32_t)_FLASH_FAT_START);
    
    __enable_irq();
    
    int ret = flash_simple_write((uint32_t)_FLASH_FAT_START, FILE_ALLOCATION_TABLE, sizeof(FILE_ALLOCATION_TABLE));
    
    return ret;
}

/**
 * @brief Writes a file and its FAT entry to flash memory.
 * * Calculates the required flash pages, updates the FAT with the UUID and 
 * boundaries, and commits the data to non-volatile memory safely by 
 * disabling interrupts during erase/write cycles.
 * * @param slot The storage slot index (0 to MAX_FILE_COUNT - 1).
 * @param src  Pointer to the file_t structure containing the data to write.
 * @param uuid Pointer to the 16-byte UUID associated with the file.
 * * @return 0 upon success. A negative value on invalid slot or flash error.
 */
int write_file(slot_t slot, file_t *src, uint8_t *uuid) {
    unsigned int length, flash_addr;
    if (slot < 0 || slot >= MAX_FILE_COUNT) {
        return -1;
    }

    flash_addr = FILE_START_PAGE_FROM_SLOT(slot);
    length = FILE_TOTAL_SIZE(src->contents_len);
    
    // Update FAT
    memcpy(&FILE_ALLOCATION_TABLE[slot].uuid, uuid, UUID_SIZE);
    FILE_ALLOCATION_TABLE[slot].flash_addr = flash_addr;
    FILE_ALLOCATION_TABLE[slot].length = length;
    
    // 1. Store FAT (This function handles its own interrupts)
    store_fat();
    int pages_to_erase = (length + FLASH_PAGE_SIZE - 1) / FLASH_PAGE_SIZE;

    // Erase File Pages safely
    
    __disable_irq();

    for (int i = 0; i < pages_to_erase; i++) {
        flash_simple_erase_page(flash_addr + (FLASH_PAGE_SIZE * i));
    }

    __enable_irq(); 
     
    // Write File safely
    __disable_irq();

    int ret = flash_simple_write(flash_addr, src, length);

    __enable_irq();
    
    return ret;
}

/**
 * @brief Initializes the filesystem.
 * * @return 0 upon successful initialization.
 */
int init_fs() {
    return load_fat();
}

/**
 * @brief Checks if a specific filesystem slot is currently occupied.
 * * Directly queries flash memory to read the 'in_use' flag without 
 * loading the entire file structure into RAM.
 * * @param slot The storage slot index to check.
 * * @return true if the slot contains an active file, false otherwise.
 */
bool is_slot_in_use(slot_t slot) {
    if (slot < 0 || slot >= MAX_FILE_COUNT) return false;
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

/**
 * @brief Applies PKCS#7 padding to a data buffer in-place.
 * * @param data       Pointer to the buffer where padding will be appended.
 * @param data_len   Current length of the unpadded data.
 * @param block_size The block size to pad to (e.g., AES_BLOCK_SIZE).
 * * @return The new total length of the padded data.
 */
static word32 add_pkcs7_padding(uint8_t* data, word32 data_len, word32 block_size)
{
    word32 padding_len = block_size - (data_len % block_size);
    uint8_t padding_byte = (uint8_t)padding_len;

    for (word32 i = 0; i < padding_len; i++) {
        data[data_len + i] = padding_byte;
    }
    return data_len + padding_len;
}

/**
 * @brief Validates and calculates data length after stripping PKCS#7 padding.
 * * Does not physically delete the padding, but verifies its cryptographic 
 * integrity and outputs the actual unpadded plaintext length.
 * * @param data     Pointer to the padded data buffer.
 * @param data_len The total length of the padded data.
 * @param out_len  Pointer to store the resulting unpadded data length.
 * * @return 0 upon success. -1 if padding is invalid or mathematically incorrect.
 */
static int remove_pkcs7_padding(const uint8_t* data, word32 data_len, word32* out_len)
{
    if (data_len == 0 || (data_len % AES_BLOCK_SIZE) != 0) {
        return -1;
    }

    uint8_t padding_len = data[data_len - 1];
    if (padding_len == 0 || padding_len > AES_BLOCK_SIZE) {
        return -1;
    }

    for (word32 i = 0; i < padding_len; i++) {
        if (data[data_len - 1 - i] != padding_len) {
            return -1;
        }
    }

    *out_len = data_len - padding_len;
    return 0;
}

/**
 * @brief Performs AES-CBC encryption using direct block operations.
 * * @param key Pointer to the AES key.
 * @param iv  Pointer to the Initialization Vector.
 * @param in  Pointer to the plaintext input buffer.
 * @param out Pointer to the ciphertext output buffer (can overlap with input).
 * @param len Length of the data to encrypt (must be a multiple of block size).
 * * @return 0 upon success. A negative value on cryptographic failure.
 */
static int aes_cbc_encrypt_direct(const uint8_t* key, const uint8_t* iv,
                                  const uint8_t* in, uint8_t* out, word32 len)
{
    Aes ctx;
    int ret;

    if (!key || !iv || !in || !out || len == 0) return -1;
    if (len % AES_BLOCK_SIZE) return -1;

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

/**
 * @brief Performs AES-CBC decryption using direct block operations.
 * * @param key Pointer to the AES key.
 * @param iv  Pointer to the Initialization Vector.
 * @param in  Pointer to the ciphertext input buffer.
 * @param out Pointer to the plaintext output buffer (can overlap with input).
 * @param len Length of the data to decrypt (must be a multiple of block size).
 * * @return 0 upon success. A negative value on cryptographic failure.
 */
static int aes_cbc_decrypt_direct(const uint8_t* key, const uint8_t* iv,
                                  const uint8_t* in, uint8_t* out, word32 len)
{
    Aes ctx;
    int ret;

    if (!key || !iv || !in || !out || len == 0) return -1;
    if (len % AES_BLOCK_SIZE) return -1;

    ret = wc_AesSetKey(&ctx, key, AES_KEY_LEN, NULL, AES_DECRYPTION);
    if (ret != 0) {
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

    // Validate Arguments
    if (!dest || !name || (!contents_plain && contents_len != 0)) return -1;

    memset(dest, 0, sizeof(file_t));
    dest->in_use = FILE_IN_USE;
    dest->group_id = group_id; 
    strncpy(dest->name, name, MAX_NAME_SIZE - 1);
    dest->name[MAX_NAME_SIZE - 1] = '\0';

    if (contents_len > MAX_CONTENTS_SIZE) return -1;

   // Generate Random AES Key and IV 
    uint8_t aes_key[AES_KEY_LEN];
    uint8_t iv[AES_IV_LEN];

    if (generate_random_bytes(aes_key, sizeof(aes_key)) != 0) return -1;
    
    if (generate_random_bytes(iv, sizeof(iv)) != 0) {
        secure_zero(aes_key, sizeof(aes_key));
        return -1;
    }

    // Encrypt AES Key using Group's Public Write Key
    uint8_t encrypted_key_blob[ECC_BLOB_RESERVED_SIZE]; 
    uint32_t blob_actual_len = sizeof(encrypted_key_blob);
    
    ret = encrypt_data(group_id, aes_key, AES_KEY_LEN, encrypted_key_blob, &blob_actual_len);
    
    if (ret != 0) {
        secure_zero(aes_key, sizeof(aes_key));
        return ret;
    }

    if (blob_actual_len > ECC_BLOB_RESERVED_SIZE) {
        secure_zero(aes_key, sizeof(aes_key));
        return -1;
    }

    // Check Capacity and Calculate Padding
    uint32_t pad_val = AES_BLOCK_SIZE - (contents_len % AES_BLOCK_SIZE);
    uint32_t padded_len = contents_len + pad_val;
    const uint32_t overhead = ECC_BLOB_RESERVED_SIZE + AES_IV_LEN;

    if (overhead + padded_len > MAX_ENCRYPTED_SIZE) {
        secure_zero(aes_key, sizeof(aes_key));
        return -1;
    }

    // Write Header and Encrypt In-Place
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

    // Cleanup Sensitive Data
    secure_zero(aes_key, sizeof(aes_key));

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
    (void)name;
    int ret;

    if (!src || !out_plain || !out_plain_len) return -1;

    if (src->contents_len < TOTAL_HEADER_LEN) return -1;

    // Pointers into the file buffer
    const uint8_t* key_blob = src->contents;
    const uint8_t* iv = src->contents + ECC_BLOB_RESERVED_SIZE;
    const uint8_t* ciphertext = src->contents + TOTAL_HEADER_LEN;
    const word32 ciphertext_len = (word32)src->contents_len - TOTAL_HEADER_LEN;

    if (ciphertext_len == 0 || (ciphertext_len % AES_BLOCK_SIZE) != 0) return -1;

    // Decrypt the AES Key Blob using Group Private Key
    uint8_t decrypted_aes_key[AES_KEY_LEN];
    uint32_t decrypted_key_len = sizeof(decrypted_aes_key);

    uint32_t actual_blob_size = 65 + AES_IV_SIZE + AES_KEY_LEN; 

    ret = decrypt_data(group_id, key_blob, actual_blob_size, decrypted_aes_key, &decrypted_key_len);

    if (ret != 0) return ret;

    if (decrypted_key_len != AES_KEY_LEN) {
        secure_zero(decrypted_aes_key, sizeof(decrypted_aes_key));
        return -1;
    }

    // Decrypt the Body directly into 'out_plain'
    if (*out_plain_len < ciphertext_len) {
        secure_zero(decrypted_aes_key, sizeof(decrypted_aes_key));
        return -1;
    }

    ret = aes_cbc_decrypt_direct(decrypted_aes_key, iv, ciphertext, out_plain, ciphertext_len);
    secure_zero(decrypted_aes_key, sizeof(decrypted_aes_key));

    if (ret != 0) return ret;
    
    // Remove Padding in-place
    word32 actual_len = 0;
    
    ret = remove_pkcs7_padding(out_plain, ciphertext_len, &actual_len);
    if (ret != 0) {
        secure_zero(out_plain, ciphertext_len); 
        return ret;
    }

    // Copy to Output
    *out_plain_len = (uint16_t)actual_len;
    secure_zero(out_plain + actual_len, ciphertext_len - actual_len);

    return 0;
}

int read_file(slot_t slot, file_t *dest) {
    int flash_addr, file_size;

    if (slot < 0 || slot >= MAX_FILE_COUNT) return -1;
    
    flash_addr = FILE_ALLOCATION_TABLE[slot].flash_addr;
    file_size = FILE_ALLOCATION_TABLE[slot].length;

    if (flash_addr < 0 || file_size < 0) return -1;
    flash_simple_read(flash_addr, dest, file_size);

    return 0;
}

/**
 * @brief Retrieves a pointer to a specific file's FAT metadata entry.
 * * @param slot The storage slot index.
 * * @return Pointer to the filesystem_entry_t for the given slot.
 */
const filesystem_entry_t *get_file_metadata(slot_t slot) {
    return &FILE_ALLOCATION_TABLE[slot];
}