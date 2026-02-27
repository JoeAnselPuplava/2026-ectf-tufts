/**
 * @file    security.c
 * @author  Ming Dynasty
 * @brief   Crypto functions for HSM
 * @date    2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
 */

#include <stdio.h> 
#include <string.h>
#include "security.h"
#include "secrets.h"
#include "host_messaging.h"
#include "board_random.h"

// WolfSSL Includes
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/cmac.h>

static char dbg_buf[128];

// --- Configuration ---
#define ECTF_CURVE_ID   ECC_SECP256R1
#define ECC_KEY_SIZE    32 

// --- Global Caching & State ---
static ecc_key cached_encrypt_group_key;
static uint16_t cached_encrypt_group_id = 0xFFFF;

static ecc_key cached_decrypt_group_priv_key;
static uint16_t cached_decrypt_group_id = 0xFFFF;

static WC_RNG global_rng;
static bool crypto_initialized = false;

// --- Initialization ---
int init_crypto_engine(void) {
    if (!crypto_initialized) {
        if (wc_InitRng(&global_rng) != 0) {
            return -1; 
        }
        crypto_initialized = true;
    }
    return 0;
}

// --- Existing Functions ---
bool constant_time_compare(uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

bool check_pin(unsigned char *pin) {
    print_debug(pin);
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

int encrypt_data(uint16_t group_id, const uint8_t* input, uint32_t input_len, uint8_t* output, uint32_t* output_len) {
    ecc_key ephemeral_key;
    Aes aes;
    // static ecc_key ephemeral_key;
    // static Aes aes;

    int ret;
    uint8_t shared_secret[32]; 
    word32 secret_len = sizeof(shared_secret);
    uint8_t aes_key[WC_SHA256_DIGEST_SIZE];
    uint8_t iv[AES_IV_SIZE];
    uint32_t ephemeral_pub_len = 65; 

    if (init_crypto_engine() != 0) return -1;
    if (!validate_permission(group_id, PERM_WRITE)) return PERMISSION_DENIED;

    // 1. KEY CACHING LOGIC
    if (group_id != cached_encrypt_group_id) {
        if (cached_encrypt_group_id != 0xFFFF) wc_ecc_free(&cached_encrypt_group_key);
        
        const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
        if (!secrets || secrets->write_key[0] == 0) return BAD_FUNC_ARG;

        wc_ecc_init(&cached_encrypt_group_key);
        
        // --- THE FIX ---
        // Revert this back to x963, which is compiled in by default
        ret = wc_ecc_import_x963(secrets->write_key, sizeof(secrets->write_key), &cached_encrypt_group_key);
        
        if (ret != 0) return ret;
        
        cached_encrypt_group_id = group_id;
    }

    // wc_ecc_init(&ephemeral_key);
    // ret = wc_ecc_make_key(&global_rng, 32, &ephemeral_key);
    // if (ret != 0) goto cleanup;

    // ret = wc_ecc_shared_secret(&ephemeral_key, &cached_encrypt_group_key, shared_secret, &secret_len);
    // if (ret != 0) goto cleanup;

    // wc_Sha256Hash(shared_secret, secret_len, aes_key);

    // ret = wc_RNG_GenerateBlock(&global_rng, iv, AES_IV_SIZE);
    // if (ret != 0) goto cleanup;
   wc_ecc_init(&ephemeral_key);
    
    // TRNG Retry Loop for Ephemeral Key Generation
    // We give the hardware up to 500ms to generate this one key safely
    // int retries = 10;
    // while (retries-- > 0) {
    //     ret = wc_ecc_make_key(&global_rng, 32, &ephemeral_key);
    //     if (ret == 0) break;
    //     DL_Common_delayCycles(1600000); // 50ms delay to let TRNG recover
    // }
    // if (ret != 0) goto cleanup;
    ret = wc_ecc_make_key(&global_rng, 32, &ephemeral_key);
    if (ret != 0) goto cleanup;

    ret = wc_ecc_shared_secret(&ephemeral_key, &cached_encrypt_group_key, shared_secret, &secret_len);
    if (ret != 0) goto cleanup;

    wc_Sha256Hash(shared_secret, secret_len, aes_key);

    // THE FIX: Use our lightning-fast Software PRNG for the AES IV!
    // This removes 16 bytes of heavy load from the hardware TRNG
    ret = generate_random_bytes(iv, AES_IV_SIZE);
    if (ret != 0) goto cleanup;

    ret = wc_ecc_export_x963(&ephemeral_key, output, &ephemeral_pub_len);
    if (ret != 0) goto cleanup;

    memcpy(output + ephemeral_pub_len, iv, AES_IV_SIZE);

    wc_AesSetKey(&aes, aes_key, AES_KEY_SIZE, iv, AES_ENCRYPTION);
    ret = wc_AesCbcEncrypt(&aes, output + ephemeral_pub_len + AES_IV_SIZE, input, input_len);
    
    if (ret == 0) *output_len = ephemeral_pub_len + AES_IV_SIZE + input_len;

cleanup:
    wc_ecc_free(&ephemeral_key);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    return ret;
}

int decrypt_data(uint16_t group_id, const uint8_t* input, uint32_t input_len, uint8_t* output, uint32_t* output_len) {
    ecc_key ephemeral_pub_key; 
    Aes aes;
    // static ecc_key ephemeral_pub_key; 
    // static Aes aes;

    int ret;
    uint8_t shared_secret[32];
    word32 secret_len = sizeof(shared_secret);
    uint8_t aes_key[WC_SHA256_DIGEST_SIZE];
    uint32_t header_len = 65 + AES_IV_SIZE;

    // We will use this to format our debug strings
    char local_dbg[128]; 

    if (init_crypto_engine() != 0) return -1;
    if (!validate_permission(group_id, PERM_READ)) return PERMISSION_DENIED;
    
    // 1. KEY CACHING LOGIC
    if (group_id != cached_decrypt_group_id) {
        print_debug("----------------------------------------");
        sprintf(local_dbg, "decrypt_data: Loading keys for Group 0x%04X", group_id);
        print_debug(local_dbg);
        
        if (cached_decrypt_group_id != 0xFFFF) wc_ecc_free(&cached_decrypt_group_priv_key);

        const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
        if (!secrets) {
            print_debug("decrypt_data: get_group_secrets returned NULL!");
            return BAD_FUNC_ARG;
        }

        // --- THE DEBUG PROBES ---
        sprintf(local_dbg, "DEBUG: read_key[0]=0x%02X, write_key[0]=0x%02X", secrets->read_key[0], secrets->write_key[0]);
        print_debug(local_dbg);

        if (secrets->read_key[0] == 0x00 && secrets->read_key[1] == 0x00) {
            print_debug("CRITICAL FAIL: Private read_key is all zeros! Device lacks PERM_READ.");
        }
        if (secrets->write_key[0] == 0x00 && secrets->write_key[1] == 0x00) {
            print_debug("CRITICAL FAIL: Public write_key is all zeros! PCT will fail (-173).");
            print_debug("               Did you run gen_secrets.py and re-flash the board?");
        }

        wc_ecc_init(&cached_decrypt_group_priv_key);

        // --- THE MISSING LINK ---
        // Attach the hardware RNG so ECDH can perform timing resistance blinding!
        // Without this, wc_ecc_shared_secret throws -173.
        wc_ecc_set_rng(&cached_decrypt_group_priv_key, &global_rng);

        print_debug("decrypt_data: Calling wc_ecc_import_private_key_ex...");
        
        // SATISFY PAIRWISE CONSISTENCY TEST
        ret = wc_ecc_import_private_key_ex(
            secrets->read_key, sizeof(secrets->read_key),     
            secrets->write_key, sizeof(secrets->write_key),   
            &cached_decrypt_group_priv_key,
            ECTF_CURVE_ID 
        );

        sprintf(local_dbg, "decrypt_data: Import returned %d", ret);
        print_debug(local_dbg);

        if (ret != 0) return ret;
        
        print_debug("decrypt_data: PCT Passed! Key cached.");
        print_debug("----------------------------------------");
        cached_decrypt_group_id = group_id;
    }

    // 2. Import Ephemeral Public Key from Input
    wc_ecc_init(&ephemeral_pub_key);
    ret = wc_ecc_import_x963_ex(input, 65, &ephemeral_pub_key, ECTF_CURVE_ID);
    if (ret != 0) {
        sprintf(local_dbg, "decrypt_data: Ephemeral Pub Import failed %d", ret);
        print_debug(local_dbg);
        goto cleanup;
    }

    // 3. Derive Shared Secret (ECDH)
    ret = wc_ecc_shared_secret(&cached_decrypt_group_priv_key, &ephemeral_pub_key, shared_secret, &secret_len);
    if (ret != 0) {
        sprintf(local_dbg, "decrypt_data: ECDH Shared Secret failed %d", ret);
        print_debug(local_dbg);
        goto cleanup;
    }

    // 4. KDF and Decrypt
    wc_Sha256Hash(shared_secret, secret_len, aes_key);

    const uint8_t* iv = input + 65;
    const uint8_t* ciphertext = input + header_len;
    uint32_t cipher_len = input_len - header_len;

    wc_AesSetKey(&aes, aes_key, AES_KEY_SIZE, iv, AES_DECRYPTION);
    ret = wc_AesCbcDecrypt(&aes, output, ciphertext, cipher_len);
    
    if (ret == 0) {
        *output_len = cipher_len;
        print_debug("decrypt_data: AES Decrypt SUCCESS!");
    } else {
        sprintf(local_dbg, "decrypt_data: AES Decrypt failed %d", ret);
        print_debug(local_dbg);
    }

cleanup:
    wc_ecc_free(&ephemeral_pub_key);
    secure_zero(shared_secret, sizeof(shared_secret));
    secure_zero(aes_key, sizeof(aes_key));
    return ret;
}


int sign_data(uint16_t group_id, uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t* sig_len) {
    static ecc_key cached_sign_key;
    static uint16_t cached_sign_group_id = 0xFFFF;
    char local_dbg[128]; 
    int ret;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];

    if (init_crypto_engine() != 0) return -1;
    if (!validate_permission(group_id, PERM_RECEIVE)) return PERMISSION_DENIED;

    // 1. KEY CACHING LOGIC
    print_debug("KEY CACHING LOGIC");
    if (group_id != cached_sign_group_id) {
        if (cached_sign_group_id != 0xFFFF) wc_ecc_free(&cached_sign_key);

        const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
        
        // FIX: Added curly braces
        if (!secrets || secrets->verify_key[0] == 0) {
            print_error("secrets->verify_key"); 
            return BAD_FUNC_ARG;
        }

        wc_ecc_init(&cached_sign_key);
        
        // Attach RNG for signing operations
        wc_ecc_set_rng(&cached_sign_key, &global_rng);

        // Import the Group's Private verify_key (and the check_key for consistency tests)
        ret = wc_ecc_import_private_key_ex(
            secrets->verify_key, sizeof(secrets->verify_key),     
            secrets->check_key, sizeof(secrets->check_key),   
            &cached_sign_key,
            ECTF_CURVE_ID 
        );

        // FIX: Added curly braces
        if (ret != 0) {
            print_error("PRIVATE KEY FAILED"); 
            return ret;
        }
        cached_sign_group_id = group_id;
    }

    // 2. Hash the raw input data (ECDSA signs a hash, not the raw text)
    ret = wc_Sha256Hash(input, input_len, hash);
    
    // FIX: Added curly braces
    if (ret != 0) {
        print_error("HASH FAILED"); 
        return ret;
    }

    // 3. Generate the ECDSA Signature
    ret = wc_ecc_sign_hash(
        hash, 
        sizeof(hash), 
        signature, 
        sig_len, 
        &global_rng, 
        &cached_sign_key);
    sprintf(local_dbg, "sign ret: %d", ret);
    print_debug(local_dbg);
    return ret; // 0 on success
}

int check_signature(uint16_t group_id, uint8_t* input, uint32_t input_len,  uint8_t* signature, uint32_t sig_len) {
    static ecc_key cached_check_key;
    static uint16_t cached_check_group_id = 0xFFFF;
    
    int ret;
    int verify_status = 0;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];

    if (init_crypto_engine() != 0) return -1;

    // 1. KEY CACHING LOGIC
    if (group_id != cached_check_group_id) {
        if (cached_check_group_id != 0xFFFF) wc_ecc_free(&cached_check_key);

        const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
        if (!secrets || secrets->check_key[0] == 0) return BAD_FUNC_ARG;

        wc_ecc_init(&cached_check_key);

        // Import the Group's Public check_key
        ret = wc_ecc_import_x963_ex(
            secrets->check_key, sizeof(secrets->check_key), 
            &cached_check_key, ECTF_CURVE_ID
        );
        
        if (ret != 0) return ret;
        cached_check_group_id = group_id;
    }

    // 2. Hash the raw input data to compare against the signature
    ret = wc_Sha256Hash(input, input_len, hash);
    if (ret != 0) return ret;

    // 3. Verify the ECDSA Signature
    ret = wc_ecc_verify_hash(
        signature, sig_len, 
        hash, sizeof(hash), 
        &verify_status, &cached_check_key
    );
    
    if (ret != 0) {
        return ret; // Crypto library error
    }
    
    if (verify_status != 1) {
        return -1; // Signature is INVALID (Tampered or wrong key)
    }

    return 0; // Signature is VALID
}

static void serialize_permission(uint8_t *out, group_permission_t *perm) {
    // group_id in big-endian
    out[0] = (perm->group_id >> 8) & 0xFF;
    out[1] = perm->group_id & 0xFF;

    out[2] = perm->read    ? 1 : 0;
    out[3] = perm->write   ? 1 : 0;
    out[4] = perm->receive ? 1 : 0;
}

static void deserialize_permission(const uint8_t *in, group_permission_t *perm) {
    // group_id was big-endian
    perm->group_id = ((uint16_t)in[0] << 8) | (uint16_t)in[1];

    perm->read    = in[2] ? true : false;
    perm->write   = in[3] ? true : false;
    perm->receive = in[4] ? true : false;
}

static void serialize_request(uint8_t *buffer, interrogate_request_t *req) {
    uint32_t offset = 0;

    for (uint32_t i = 0; i < MAX_PERMS; i++) {
        serialize_permission(&buffer[offset], &req->permissions[i]);
        offset += PERM_SERIALIZED_SIZE;
    }
}

static void deserialize_request(const uint8_t *buffer, interrogate_request_t *req) {
    uint32_t offset = 0;

    for (uint32_t i = 0; i < MAX_PERMS; i++) {
        deserialize_permission(&buffer[offset],
                               &req->permissions[i]);
        offset += PERM_SERIALIZED_SIZE;
    }
}

static void pad_request(uint8_t *buffer) {
    for (uint32_t i = 0; i < REQUEST_PAD_LEN; i++)
        buffer[REQUEST_SERIALIZED_SIZE + i] = REQUEST_PAD_LEN; 
}

uint8_t encrypt_perms(interrogate_request_t *request, uint8_t *enc_request) { 
    int ret; 
    Aes aes; 
    uint8_t padded[REQUEST_SERIALIZED_SIZE + AES_BLOCK_SIZE];
    uint8_t iv[AES_IV_SIZE];

    // zeroize the buffers we will use
    memset(padded, 0, sizeof(padded));

    // create iv 
    // uncomment after everything is merged and can access generate_random_bytes
    ret = generate_random_bytes(iv, AES_IV_SIZE);
    if (ret != 0) return ret;

    // initialize aes 
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    // set the key 
    ret = wc_AesSetKey(&aes, INTERROGATE_AES_KEY, AES_KEY_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0) return ret;

    // convert and pad request 
    serialize_request(padded, request);
    pad_request(padded);

    // append the iv to the front of the encrypted data 
    memcpy(enc_request, iv, AES_IV_SIZE);

    // encrypt the data 
    ret = wc_AesCbcEncrypt(&aes, enc_request+AES_IV_SIZE, padded, REQUEST_PADDED_SIZE);
    if (ret != 0) return ret;

    // free everything 
    wc_AesFree(&aes);

    return ret; 
}

uint8_t decrypt_perms(interrogate_request_t *request, uint8_t *enc_request) {
    int ret; 
    Aes aes; 
    uint8_t decrypted[REQUEST_SERIALIZED_SIZE + AES_BLOCK_SIZE];
    uint8_t iv[AES_IV_SIZE]; 

    // zeroize the buffers we will use
    memset(decrypted, 0, sizeof(decrypted));
    memset(iv, 0, sizeof(iv));

    // initialize aes 
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return ret;


    // extract the iv from the buffer
    memcpy(iv, enc_request, AES_IV_SIZE);

    // set the key 
    ret = wc_AesSetKey(&aes, INTERROGATE_AES_KEY, AES_KEY_SIZE, iv, AES_DECRYPTION);
    if (ret != 0) return ret;

    // decrypt the data 
    ret = wc_AesCbcDecrypt(&aes, decrypted, enc_request+AES_IV_SIZE, REQUEST_PADDED_SIZE);
    if (ret != 0) return ret;

    wc_AesFree(&aes);

    // deserialize (unpadding not needed because all sizes are constant)
    deserialize_request(decrypted, request);   

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
// Add this near the top of security.c with your other includes
extern void DL_Common_delayCycles(uint32_t cycles);

// --- Global Software PRNG State ---
static uint8_t prng_seed[32];
static uint32_t prng_counter = 0;
static bool prng_seeded = false;

// Add this extern so we can talk to the hardware directly

int generate_random_bytes(uint8_t *output, uint32_t length) {
    if (!prng_seeded) {
        if (init_crypto_engine() != 0) return -1;
        
        print_debug("PRNG: Gathering hardware entropy for master seed...");
        DL_Common_delayCycles(3200000); 
        
        for(int i = 0; i < 32; i += 4) {
            int hardware_retries = 20;
            
            // THE FIX: Call the hardware driver directly to avoid infinite recursion!
            while(mspm0_trng_seed(prng_seed + i, 4) != 0) {
                DL_Common_delayCycles(640000); 
                if (--hardware_retries == 0) return -1; 
            }
        }
        prng_seeded = true;
        print_debug("PRNG: Master seed secured!");
    }

    // Software PRNG: SHA-256(Seed || Counter)
    // This is infinitely fast and will never exhaust the hardware!
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    uint32_t generated = 0;
    
    while (generated < length) {
        wc_Sha256 sha;
        wc_InitSha256(&sha);
        wc_Sha256Update(&sha, prng_seed, 32);
        wc_Sha256Update(&sha, (uint8_t*)&prng_counter, sizeof(prng_counter));
        wc_Sha256Final(&sha, hash);
        wc_Sha256Free(&sha);
        
        prng_counter++;
        
        uint32_t take = (length - generated > 32) ? 32 : (length - generated);
        memcpy(output + generated, hash, take);
        generated += take;
    }
    
    return 0;
}
int sign_data_cmac(uint16_t group_id, uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t* sig_len) {
    Cmac cmac;
    int ret;
    word32 outLen = WC_AES_BLOCK_SIZE; // Use standard AES block size (16 bytes)

    print_debug("init_crypto_engine");
    if (init_crypto_engine() != 0) return -1;

    // Initialize CMAC with AES-256
    print_debug("Initialize CMAC with AES-256");
    ret = wc_InitCmac(&cmac, RECEIVE_AES_KEY, 32, WC_CMAC_AES, NULL);
    if (ret != 0) return ret;

    // Update the CMAC with the input data
    print_debug("wc_CmacUpdate");
    ret = wc_CmacUpdate(&cmac, input, input_len);
    if (ret != 0) {
        secure_zero(&cmac, sizeof(cmac));
        return ret;
    }

    // Generate the final 16-byte MAC
    print_debug("GENERATING CMAC");
    ret = wc_CmacFinal(&cmac, signature, &outLen);
    if (ret == 0) {
        *sig_len = (uint32_t)outLen;
    }

    // Clean up
    print_debug("DONE SIGNING");
    secure_zero(&cmac, sizeof(cmac));
    return ret; 
}

int check_signature_cmac(uint16_t group_id, uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t sig_len) {
    uint8_t expected_mac[WC_AES_BLOCK_SIZE];
    uint32_t expected_mac_len = WC_AES_BLOCK_SIZE;
    int ret;

    if (init_crypto_engine() != 0) return -1;
    if (!validate_permission(group_id, PERM_RECEIVE)) return PERMISSION_DENIED;

    // Fast fail: AES-CMAC must always be exactly 16 bytes
    if (sig_len != WC_AES_BLOCK_SIZE) {
        print_debug("check_signature_cmac: Invalid CMAC length");
        return -1; 
    }

    // To verify a MAC, we just re-calculate it locally using the exact same data and key
    ret = sign_data_cmac(group_id, input, input_len, expected_mac, &expected_mac_len);
    if (ret != 0) return ret;

    // Use constant-time comparison to prevent timing side-channel attacks!
    if (!constant_time_compare(expected_mac, signature, WC_AES_BLOCK_SIZE)) {
        print_debug("check_signature_cmac: CMAC mismatch (Tampered or Wrong Key)!");
        secure_zero(expected_mac, sizeof(expected_mac));
        return -1; 
    }

    secure_zero(expected_mac, sizeof(expected_mac));
    return 0; // Signature is VALID
}