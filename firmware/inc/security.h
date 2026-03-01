/**
 * @file security.h
 * @author Ming Dynasty
 * @brief Header for security checks and secret management
 * @date 2026
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include <wolfssl/wolfcrypt/aes.h>

#define MAX_PERMS 8
#define PIN_LENGTH 6

// --- SECP256R1 Key Sizes ---
// Private Key is a 32-byte scalar
#define ECC_PRIV_KEY_SIZE 32

// Public Key is 33 bytes (Compressed: 0x02/0x03 + X coordinate)
#define ECC_PUB_KEY_SIZE  65

// Max Signature Size (DER encoded ECDSA signature for P-256 is usually ~70-72 bytes)
#define ECC_SIG_SIZE      80

// Estimated Encryption Overhead (Ephemeral Key + Tag + Mac). 
// Output buffers for encryption should be at least INPUT_LEN + ECC_MSG_OVERHEAD
#define ECC_MSG_OVERHEAD  128

#define PERMISSION_DENIED -1

// #define AES_IV_SIZE              16
// #define AES_BLOCK_SIZE           16
#define AES_KEY_SIZE             32

#define PERM_SERIALIZED_SIZE      5
#define REQUEST_SERIALIZED_SIZE  (MAX_PERMS * PERM_SERIALIZED_SIZE) // 8 * 5 = 40 bytes
#define REQUEST_PAD_LEN          (AES_BLOCK_SIZE - (REQUEST_SERIALIZED_SIZE % AES_BLOCK_SIZE)) // 16 - 40 % 16 = 8 bytes
#define REQUEST_PADDED_SIZE      (REQUEST_SERIALIZED_SIZE + REQUEST_PAD_LEN) // 48 bytes

typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

typedef struct {
    group_permission_t permissions[MAX_PERMS];
} interrogate_request_t; 

/** @brief Validate a pin against the HSM's pin */
bool check_pin(unsigned char *pin);

/** @brief Ensure the HSM has the requested permission */
bool validate_permission(uint16_t group_id, permission_enum_t perm);

/** @brief Retrieve the secrets (keys) for a specific group. */
const void* get_group_secrets(uint16_t group_id);

/** * @brief Encrypts data using the Group's Write Key (Public Key).
 * Requires PERM_WRITE.
 * @param group_id The group ID to use.
 * @param input Pointer to data to encrypt.
 * @param input_len Length of input data.
 * @param output Pointer to buffer for encrypted data. MUST be larger than input! (See ECC_MSG_OVERHEAD)
 * @param output_len In: Size of output buffer. Out: Bytes written.
 * @return 0 on success, non-zero on error.
 */
int encrypt_data(uint16_t group_id, const uint8_t* input, uint32_t input_len, uint8_t* output, uint32_t* output_len);

/** * @brief Decrypts data using the Group's Read Key (Private Key).
 * Requires PERM_READ.
 * @param group_id The group ID to use.
 * @param input Pointer to encrypted data.
 * @param input_len Length of encrypted data.
 * @param output Pointer to buffer for decrypted data.
 * @param output_len In: Size of output buffer. Out: Bytes written.
 * @return 0 on success, non-zero on error.
 */
int decrypt_data(uint16_t group_id, const uint8_t* input, uint32_t input_len, uint8_t* output, uint32_t* output_len);

/** * @brief Signs data using the Group's Verify Key (Private Key).
 * Requires PERM_RECEIVE.
 * @param group_id The group ID to use.
 * @param input Pointer to data to sign.
 * @param input_len Length of input data.
 * @param signature Pointer to buffer for the signature.
 * @param sig_len In: Size of sig buffer (Use ECC_SIG_SIZE). Out: Bytes written.
 * @return 0 on success, non-zero on error.
 */
int sign_data(uint16_t group_id, uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t* sig_len);

/** * @brief Checks (verifies) a signature using the Group's Check Key (Public Key).
 * Requires PERM_RECEIVE.
 * @param group_id The group ID to use.
 * @param input Pointer to the original data.
 * @param input_len Length of input data.
 * @param signature Pointer to the signature to verify.
 * @param sig_len Length of the signature.
 * @return 0 if signature is VALID, non-zero if INVALID or error.
 */
int check_signature(uint16_t group_id, uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t sig_len);

/** * @brief Encrypts list of permissions sent by interrogating HSM to listening HSM.
 * 
 * @param request Pointer to the request containg the permissions list 
 * @param enc_request Pointer to buffer where encrypted request should be stored
 * @return 0 if encryption is successful, non-zero on error
 */
uint8_t encrypt_perms(interrogate_request_t *request, uint8_t *enc_request); 

/** * @brief Decrypts list of permissions received by listening HSM from interrogating HSM.
 * 
 * @param request Pointer to the struct where the decrypted request should be stored 
 * @param enc_request Pointer to buffer contiaing the encrypted request 
 * @return 0 if decryption is successful, non-zero on error
 */
uint8_t decrypt_perms(interrogate_request_t *request, uint8_t *enc_request); 

/** * @brief Generates an AES-CMAC authentication tag.
 * Requires PERM_RECEIVE.
 * @param group_id The group ID to use.
 * @param input Pointer to data to sign.
 * @param input_len Length of input data.
 * @param signature Pointer to buffer for the MAC.
 * @param sig_len In: Size of sig buffer. Out: Bytes written (always 16 for AES).
 * @return 0 on success, non-zero on error.
 */
int sign_data_cmac(uint16_t group_id, uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t* sig_len);

/** * @brief Verifies an AES-CMAC authentication tag.
 * Requires PERM_RECEIVE.
 * @param group_id The group ID to use.
 * @param input Pointer to the original data.
 * @param input_len Length of input data.
 * @param signature Pointer to the MAC to verify.
 * @param sig_len Length of the MAC (must be 16).
 * @return 0 if MAC is VALID, non-zero if INVALID or error.
 */
int check_signature_cmac(uint16_t group_id, uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t sig_len);

void secure_zero(void* v, size_t n);
int init_crypto_engine(void);
int generate_random_bytes(uint8_t *output, uint32_t length);
#endif  // __SECURITY_H__