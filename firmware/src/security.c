/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Implementation of security checks and crypto operations
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdio.h> // Added for sprintf
#include "security.h"
#include "secrets.h"
#include "host_messaging.h"

// WolfSSL Includes
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>
#include "board_random.h"
#include <string.h>


// --- Debug Helper ---
static char dbg_buf[128];

// --- Configuration ---
#define ECTF_CURVE_ID   ECC_SECP256R1
#define ECC_KEY_SIZE    32 
#define AES_KEY_SIZE    32
#define AES_IV_SIZE     16

// --- Existing Functions ---

bool constant_time_compare(uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

bool check_pin(unsigned char *pin) {
    uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};
    wc_Sha256 sha;
    if (wc_InitSha256(&sha) != 0) return false;
    wc_Sha256Update(&sha, pin, PIN_LENGTH);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);
    return (constant_time_compare(hash, HSM_PIN_HASH, WC_SHA256_DIGEST_SIZE));
}

const void* get_group_secrets(uint16_t group_id) {
    for(int i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            return (const void*)global_secrets[i];
        }
    }
    return NULL;
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    for(int i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            switch (perm) {
                case PERM_READ:    return global_permissions[i].read;
                case PERM_WRITE:   return global_permissions[i].write;
                case PERM_RECEIVE: return global_permissions[i].receive;
                default: return false;
            }
        }
    }
    return false;
}

// --- Crypto Operations ---

/* * Manual ECIES Encryption */
int encrypt_data(uint16_t group_id, const uint8_t* input, uint32_t input_len, uint8_t* output, uint32_t* output_len) {
    // CRITICAL FIX: Make large structs static to prevent Stack Overflow
    static ecc_key group_pub_key;
    static ecc_key ephemeral_key;
    static WC_RNG rng;
    static Aes aes;

    int ret;
    uint8_t shared_secret[32]; 
    word32 secret_len = sizeof(shared_secret);
    uint8_t aes_key[WC_SHA256_DIGEST_SIZE];
    uint8_t iv[AES_IV_SIZE];
    uint32_t ephemeral_pub_len = ECC_PUB_KEY_SIZE;

    print_debug("encrypt_data: Enter");
    sprintf(dbg_buf, "encrypt_data: Group 0x%04X, InputLen %d", group_id, (int)input_len);
    print_debug(dbg_buf);

    if (!validate_permission(group_id, PERM_WRITE)) {
        print_debug("encrypt_data: PERM_WRITE Denied");
        return PERMISSION_DENIED;
    }
    
    const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
    if (!secrets) {
        print_debug("encrypt_data: Secrets not found for group");
        return BAD_FUNC_ARG;
    }

    ret = wc_InitRng(&rng); 
    if (ret != 0) {
        sprintf(dbg_buf, "encrypt_data: wc_InitRng failed %d", ret);
        print_debug(dbg_buf);
        return ret;
    }

    // 1. Initialize and Load (Standard Import)
    wc_ecc_init(&ephemeral_key);
    wc_ecc_init(&group_pub_key);

    // Attach the RNG to the keys so Timing Resistance blinding doesn't fail!
    // wc_ecc_set_rng(&group_pub_key, &rng);
    // wc_ecc_set_rng(&ephemeral_key, &rng);
    
    print_debug("encrypt_data: Loading Group Public Key...");
    ret = wc_ecc_import_x963(secrets->write_key, sizeof(secrets->write_key), &group_pub_key);
    
    if (ret != 0) {
        sprintf(dbg_buf, "encrypt_data: Load Key failed? %d", ret);
        print_debug(dbg_buf);
        goto cleanup_rng;
    }

    // 2. Generate Ephemeral Key Pair (Standard Make Key - 32 bytes defaults to P-256)
    print_debug("encrypt_data: Generating Ephemeral Key...");
    ret = wc_ecc_make_key(&rng, 32, &ephemeral_key);
    if (ret != 0) {
        sprintf(dbg_buf, "encrypt_data: Make Key failed %d", ret);
        print_debug(dbg_buf);
        goto cleanup_keys;
    }

    // 3. Derive Shared Secret (Standard ECDH)
    print_debug("encrypt_data: Deriving Shared Secret...");
    ret = wc_ecc_shared_secret(&ephemeral_key, &group_pub_key, shared_secret, &secret_len);
    if (ret != 0) {
        sprintf(dbg_buf, "encrypt_data: ECDH Shared Secret failed %d", ret);
        print_debug(dbg_buf);
        goto cleanup_keys;
    }

    // 4. Derive AES Key (SHA256 of Shared Secret)
    wc_Sha256Hash(shared_secret, secret_len, aes_key);

    // 5. Encrypt (AES-CBC)
    ret = wc_RNG_GenerateBlock(&rng, iv, AES_IV_SIZE);
    if (ret != 0) goto cleanup_keys;

    // Standard Export
    ret = wc_ecc_export_x963(&ephemeral_key, output, &ephemeral_pub_len);
    if (ret != 0) {
        sprintf(dbg_buf, "encrypt_data: Export Ephemeral Key failed %d", ret);
        print_debug(dbg_buf);
        goto cleanup_keys;
    }

    memcpy(output + ephemeral_pub_len, iv, AES_IV_SIZE);

    wc_AesSetKey(&aes, aes_key, AES_KEY_SIZE, iv, AES_ENCRYPTION);
    ret = wc_AesCbcEncrypt(&aes, output + ephemeral_pub_len + AES_IV_SIZE, input, input_len);
    
    if (ret == 0) {
        *output_len = ephemeral_pub_len + AES_IV_SIZE + input_len;
        print_debug("encrypt_data: Success");
    } else {
        sprintf(dbg_buf, "encrypt_data: AES Encrypt failed %d", ret);
        print_debug(dbg_buf);
    }
    cleanup_keys:
        wc_ecc_free(&group_pub_key);
        wc_ecc_free(&ephemeral_key);
    cleanup_rng:
        wc_FreeRng(&rng);
        return ret;
}

static ecc_key cached_group_priv_key;
static uint16_t cached_decrypt_group_id = 0xFFFF;

int decrypt_data(uint16_t group_id, const uint8_t* input, uint32_t input_len, uint8_t* output, uint32_t* output_len) {
    static ecc_key ephemeral_pub_key; // Keep static for RAM safety
    static Aes aes;

    int ret;
    uint8_t shared_secret[32];
    word32 secret_len = sizeof(shared_secret);
    uint8_t aes_key[WC_SHA256_DIGEST_SIZE];
    uint32_t header_len = ECC_PUB_KEY_SIZE + AES_IV_SIZE;

    if (!validate_permission(group_id, PERM_READ)) return PERMISSION_DENIED;
    
    // 1. KEY CACHING LOGIC (Speed Boost)
    if (group_id != cached_decrypt_group_id) {
        print_debug("decrypt_data: Group change detected, re-loading keys...");
        
        // Clean up old cached key
        if (cached_decrypt_group_id != 0xFFFF) {
            wc_ecc_free(&cached_group_priv_key);
        }

        const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
        if (!secrets) return BAD_FUNC_ARG;

        wc_ecc_init(&cached_group_priv_key);

        // Load the 32-byte private scalar directly (big-endian)
        // Using wc_ecc_import_raw is often cleaner for your Python-generated bytes
        ret = wc_ecc_import_raw(&cached_group_priv_key, NULL, NULL, 
                                secrets->read_key, "ECTF_CURVE_ID");
        if (ret != 0) return ret;

        // CRITICAL: Reconstruct the public component to satisfy ECDH validation
        // This is the slow part, but now it only runs once per group change
        ret = wc_ecc_make_pub(&cached_group_priv_key, NULL);
        if (ret != 0) return ret;

        cached_decrypt_group_id = group_id;
    }

    // 2. Import Ephemeral Public Key from Input
    wc_ecc_init(&ephemeral_pub_key);
    ret = wc_ecc_import_x963_ex(input, ECC_PUB_KEY_SIZE, &ephemeral_pub_key, ECTF_CURVE_ID);
    if (ret != 0) goto cleanup;

    // 3. Derive Shared Secret (ECDH)
    // We use the CACHED key here for speed
    ret = wc_ecc_shared_secret(&cached_group_priv_key, &ephemeral_pub_key, shared_secret, &secret_len);
    if (ret != 0) goto cleanup;

    // 4. KDF and Decrypt (Same as before)
    wc_Sha256Hash(shared_secret, secret_len, aes_key);

    const uint8_t* iv = input + ECC_PUB_KEY_SIZE;
    const uint8_t* ciphertext = input + header_len;
    uint32_t cipher_len = input_len - header_len;

    wc_AesSetKey(&aes, aes_key, AES_KEY_SIZE, iv, AES_DECRYPTION);
    ret = wc_AesCbcDecrypt(&aes, output, ciphertext, cipher_len);
    
    if (ret == 0) {
        *output_len = cipher_len;
    }

cleanup:
    // We DO NOT free cached_group_priv_key here
    wc_ecc_free(&ephemeral_pub_key);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    return ret;
}

int sign_data(uint16_t group_id, const uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t* sig_len) {
    // CRITICAL FIX: Make large structs static
    // static ecc_key key;
    // static WC_RNG rng;
    // static wc_Sha256 sha;

    // int ret;
    // uint8_t hash[WC_SHA256_DIGEST_SIZE];

    // print_debug("sign_data: Start");

    // if (!validate_permission(group_id, PERM_RECEIVE)) return PERMISSION_DENIED;
    // const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
    // if (!secrets) return BAD_FUNC_ARG;

    // // Load VERIFY KEY (Private)
    // ret = wc_ecc_import_x963_ex(&key, secrets->verify_key, sizeof(secrets->verify_key), NULL, 0);
    // if (ret != 0) return ret;

    // // Initialize RNG
    // // ret = mspm0_trng_seed(&rng, sizeof(rng));
    // // if (ret != 0) { wc_ecc_free(&key); return ret; }

    // // Hash the data
    // wc_InitSha256(&sha);
    // wc_Sha256Update(&sha, input, input_len);
    // wc_Sha256Final(&sha, hash);
    // wc_Sha256Free(&sha);

    // // Sign the hash
    // print_debug("sign_data: Computing ECDSA Signature...");
    // ret = wc_ecc_sign_hash(hash, sizeof(hash), signature, sig_len, &rng, &key);
    // if (ret != 0) {
    //     sprintf(dbg_buf, "sign_data: Sign Hash failed %d", ret);
    //     print_debug(dbg_buf);
    // }

    // wc_FreeRng(&rng);
    // wc_ecc_free(&key);
    // return ret;
    return 0;
}

int check_signature(uint16_t group_id, const uint8_t* input, uint32_t input_len, const uint8_t* signature, uint32_t sig_len) {
    // CRITICAL FIX: Make large structs static
    // static ecc_key key;
    // static wc_Sha256 sha;

    // int ret;
    // int is_valid = 0;
    // uint8_t hash[WC_SHA256_DIGEST_SIZE];

    // print_debug("check_signature: Start");

    // if (!validate_permission(group_id, PERM_RECEIVE)) return PERMISSION_DENIED;
    // const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
    // if (!secrets) return BAD_FUNC_ARG;

    // // Load CHECK KEY (Public)
    // ret = wc_ecc_import_x963_ex(&key, NULL, 0, secrets->check_key, sizeof(secrets->check_key));
    // ret = wc_ecc_import_x963_ex(secrets->write_key, sizeof(secrets->write_key), &group_pub_key);
    // if (ret != 0) return ret;

    // // Hash the data
    // wc_InitSha256(&sha);
    // wc_Sha256Update(&sha, input, input_len);
    // wc_Sha256Final(&sha, hash);
    // wc_Sha256Free(&sha);

    // // Verify
    // print_debug("check_signature: Verifying ECDSA...");
    // ret = wc_ecc_verify_hash(signature, sig_len, hash, sizeof(hash), &is_valid, &key);
    // if (ret != 0) {
    //     sprintf(dbg_buf, "check_signature: Verification call failed %d", ret);
    //     print_debug(dbg_buf);
    // }

    // wc_ecc_free(&key);

    // if (ret == 0 && is_valid == 1) {
    //     print_debug("check_signature: Valid");
    //     return 0; // Valid
    // } else {
    //     print_debug("check_signature: Invalid");
    //     return -1; // Invalid
    // }
    return 0;
}

void secure_zero(void* v, size_t n)
{
    volatile uint8_t* p8 = (volatile uint8_t*)v;

    // 1) wipe bytes until 4-byte aligned
    while (n && (((uintptr_t)p8) & 3u)) {
        *p8++ = 0;
        n--;
    }

    // 2) wipe 32-bit chunks (now aligned)
    volatile uint32_t* p32 = (volatile uint32_t*)p8;
    while (n >= sizeof(uint32_t)) {
        *p32++ = 0;
        n -= sizeof(uint32_t);
    }

    // 3) wipe remaining bytes
    p8 = (volatile uint8_t*)p32;
    while (n--) {
        *p8++ = 0;
    }
}