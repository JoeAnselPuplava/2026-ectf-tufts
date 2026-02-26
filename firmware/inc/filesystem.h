/**
 * @file filesystem.h
 * @author Ming Dynasty
 * @brief eCTF flash-based filesystem management
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __FILESYSTEM__
#define __FILESYSTEM__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "simple_flash.h"
// #include "wolfssl/wolfcrypt/rsa.h"
// #include "wolfssl/wolfcrypt/random.h"
// #include "wolfssl/wolfcrypt/sha256.h"
// #include "wolfssl/wolfcrypt/aes.h"


// #include "commands.h"

typedef unsigned char slot_t;
typedef uint16_t group_id_t;


/**********************************************************
 ********** BEGIN FUNCTIONALLY DEFINED ELEMENTS ***********
 **********************************************************/

// Everything in this section is defined by the functional requirements. Your design may
// not change the FAT scheme, address, or size of the elements. You may change the
// implementation to utilize the FAT however you like, and you may use any allocation
// scheme to determine where to store files. The pointers to files, along with their
// UUIDs MUST be at this location in flash or your design will not be functionally
// compliant.

#define MAX_FILE_COUNT 8
#define MAX_NAME_SIZE 32
#define MAX_CONTENTS_SIZE 8192

// _FLASH_FAT_START is defined by the functional specs to be the start of where the FAT
// will be stored. It is address 0x0003a000, the last flash page. Your team may NOT
// change this location as the data structure location must be known by the secure
// bootloader.
#define _FLASH_FAT_START 0x0003a000

// size of file UUID
#define UUID_SIZE 16

// This struct is functionally defined
typedef struct {
    char uuid[UUID_SIZE];
    uint16_t length;
    uint16_t padding;
    unsigned int flash_addr;
} filesystem_entry_t;

static filesystem_entry_t FILE_ALLOCATION_TABLE[MAX_FILE_COUNT];

/**********************************************************
 *********** END FUNCTIONALLY DEFINED ELEMENTS ************
 **********************************************************/

/* Encryption overhead: 128 (ECC key blob) + 16 (IV) = 144 bytes */
#define ENCRYPTION_OVERHEAD 144 

/* MAX_CONTENTS_SIZE must be at least (MAX_PLAINTEXT_SIZE + ENCRYPTION_OVERHEAD + padding) */
/* 8192 + 144 + 16 (max padding) = 8352. We'll use 8400 for safety. */
#define MAX_ENCRYPTED_SIZE 8400

/*
The new secure design allocates files for each slot right before the FAT:
0: 0x28000-0x2a400
1: 0x2a400-0x2c800
2: 0x2c800-0x2ec00
3: 0x2ec00-0x31000
4: 0x31000-0x33400
5: 0x33400-0x35800
6: 0x35800-0x37c00
7: 0x37c00-0x3a000
*/

// Calculate the flash address for a given file slot. 9 pages are allocated for each file.
#define FILE_START_PAGE_FROM_SLOT(slot) FILES_START_ADDR + (STORED_FILE_SIZE*slot)

// Calculate the total size of a file in flash, including its metadata
#define FILE_TOTAL_SIZE(len) len + offsetof(file_t, contents)

// Each file will be 9 pages in size. 8 pages for the file contents + 1 page for metadata
#define FILE_PAGE_COUNT 9
#define STORED_FILE_SIZE FLASH_PAGE_SIZE*FILE_PAGE_COUNT

// --- THE FIX ---
// Move the file storage from 64KB (0x10000) up to 160KB (0x28000) to make room for WolfSSL!
#define FILES_START_ADDR 0x28000

#define FILE_IN_USE 0xdeadbeef
// used to actually define the file object
typedef struct {
    uint32_t in_use;  // FILE_IN_USE if in use
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
    uint16_t contents_len;
    uint8_t contents[MAX_CONTENTS_SIZE];
} file_t;

/** @brief Initialize the filesystem
 *
 *
 * @return 0 upon success. A negative value on error.
*/
int init_fs();

// Utilities
void secure_zero(void* v, size_t n);

/** @brief Check whether a file is in use
 *
 *  @param slot The slot to check
 *
 * @return True if the slot is in use. False otherwise.
*/
bool is_slot_in_use(slot_t slot);

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to check
 *
 * @return 0 upon success. A negative value otherwise.
*/
// int create_file(file_t *dest, group_id_t group_id, char *name, uint16_t contents_len, uint8_t *contents);

/** @brief Create a new encrypted file object in memory
 *
 *  Uses RSA-OAEP + AES-CTR encryption
 *
 * @param dest           Destination file structure
 * @param group_id       Group ID for access control
 * @param name           Filename
 * @param contents_len   Length of plaintext
 * @param contents_plain Plaintext data
 *
 * @return 0 upon success. A negative value otherwise.
*/
int create_file(
    file_t *dest,
    group_id_t group_id,
    char *name,
    uint16_t contents_len,
    uint8_t *contents_plain
);

/** @brief Decrypt file contents
 *
 * @param src            Source encrypted file
 * @param group_id       Group ID (for future AAD binding)
 * @param name           Filename (for future AAD binding)
 * @param out_plain      Output buffer for plaintext
 * @param out_plain_len  Input: buffer size, Output: actual plaintext length
 *
 * @return 0 upon success. A negative value otherwise.
*/
int decrypt_file_contents(
    const file_t* src,
    group_id_t group_id,
    const char* name,
    uint8_t* out_plain,
    uint16_t* out_plain_len
);

/** @brief Create a new file object in memory
 *
 *  @param slot The slot to write the file to
 *  @param src The sourc file to store
 *  @param uuid The UUID to store in the FAT
 *
 * @return 0 upon success. A negative value otherwise.
*/
int write_file(slot_t slot, file_t *src, uint8_t *uuid);

/** @brief Read a file from persistent storage into memory
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *
 * @return 0 upon success. A negative value otherwise.
*/
int read_file(slot_t slot, file_t *dest);


/** @brief Get a read-only pointer to a file's metadata
 *
 *  @param slot The slot to get metadata for
 *
 * @return A filesystem_entry_t * on success. NULL on error.
*/
const filesystem_entry_t *get_file_metadata(slot_t slot);

#endif
