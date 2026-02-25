/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Implementation of security checks and crypto operations
 * @date 2026
 */

#include <stdio.h> 
#include <string.h>
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

static char dbg_buf[128];

// --- Configuration ---
#define ECTF_CURVE_ID   ECC_SECP256R1
#define ECC_KEY_SIZE    32 
#define AES_KEY_SIZE    32
#define AES_IV_SIZE     16

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

// TODO: Implement sign_data and check_signature later
int sign_data(uint16_t group_id, const uint8_t* input, uint32_t input_len, uint8_t* signature, uint32_t* sig_len) {
    static ecc_key cached_sign_key;
    static uint16_t cached_sign_group_id = 0xFFFF;
    
    int ret;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];

    if (init_crypto_engine() != 0) return -1;
    if (!validate_permission(group_id, PERM_RECEIVE)) return PERMISSION_DENIED;

    // 1. KEY CACHING LOGIC
    if (group_id != cached_sign_group_id) {
        if (cached_sign_group_id != 0xFFFF) wc_ecc_free(&cached_sign_key);

        const group_secrets_t* secrets = (const group_secrets_t*)get_group_secrets(group_id);
        if (!secrets || secrets->verify_key[0] == 0) return BAD_FUNC_ARG;

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

        if (ret != 0) return ret;
        cached_sign_group_id = group_id;
    }

    // 2. Hash the raw input data (ECDSA signs a hash, not the raw text)
    ret = wc_Sha256Hash(input, input_len, hash);
    if (ret != 0) return ret;

    // 3. Generate the ECDSA Signature
    ret = wc_ecc_sign_hash(
        hash, sizeof(hash), 
        signature, sig_len, 
        &global_rng, &cached_sign_key
    );
    
    return ret; // 0 on success
}

int check_signature(uint16_t group_id, const uint8_t* input, uint32_t input_len, const uint8_t* signature, uint32_t sig_len) {
    static ecc_key cached_check_key;
    static uint16_t cached_check_group_id = 0xFFFF;
    
    int ret;
    int verify_status = 0;
    uint8_t hash[WC_SHA256_DIGEST_SIZE];

    if (init_crypto_engine() != 0) return -1;
    if (!validate_permission(group_id, PERM_RECEIVE)) return PERMISSION_DENIED;

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