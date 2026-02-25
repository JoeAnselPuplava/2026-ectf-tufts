/**
 * @file security.c
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#include "secrets.h"
#include "security.h"
#include "host_messaging.h"
#include "commands.h"
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    uint8_t hash[WC_SHA256_DIGEST_SIZE] = {0};
    wc_Sha256 sha;

    /* Initialize SHA-256 */
    if (wc_InitSha256(&sha) != 0) {
        print_error("SHA256 init failed\n");
        return false;
    }

    /* Hash the provided PIN */
    wc_Sha256Update(&sha, pin, 6);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    // char output_buf1[128] = {0};
    // char output_buf2[128] = {0};
    // char output_buf3[128] = {0};
    // sprintf(output_buf1, "pinHash is %s\n", HSM_PIN_HASH);
    // print_debug(output_buf1);
    // sprintf(output_buf2, "pin hash is %s\n", hash);
    // print_debug(output_buf2);
    // sprintf(output_buf3, "pin given is %s\n", pin);
    // print_debug(output_buf3);
    /* Compare against stored hash */
    if (memcmp(hash, HSM_PIN_HASH, WC_SHA256_DIGEST_SIZE) == 0) {
        print_debug("PIN OK\n");
        return true;
    } else {
        print_debug("PIN INVALID\n");
        return false;
    }
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
    char output_buf[128] = {0};

    sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm, group_id);
    print_debug(output_buf);

    // TODO: the reference design doesn't implement *ANY* security.
    // This function currently does nothing. Your team should add the
    // appropriate security checks here to implement the security
    // requirements.
    for(int i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == group_id) {
            switch (perm) {
                case PERM_READ:
                    if (global_permissions[i].read) {
                        print_debug("Read permission granted\n");
                        return true;
                    }
                    break;
                case PERM_WRITE:
                    if (global_permissions[i].write) {
                        print_debug("Write permission granted\n");
                        return true;
                    }
                    break;
                case PERM_RECEIVE:
                    if (global_permissions[i].receive) {
                        print_debug("Receive permission granted\n");
                        return true;
                    }
                    break;
                default:
                    print_error("Invalid permission type\n");
                    return false;
            }
        }
    }

    return false;
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
    uint8_t iv[AES_IV_SIZE] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    const byte key[AES_KEY_SIZE] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    // zeroize the buffers we will use
    memset(padded, 0, sizeof(padded));

    // create iv 
    // uncomment after everything is merged and can access generate_random_bytes
    // ret = generate_random_bytes(iv, AES_IV_SIZE);
    // if (ret != 0) return ret;

    // initialize aes 
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    // TODO: get the key from global secrets 

    // set the key 
    ret = wc_AesSetKey(&aes, key, AES_KEY_SIZE, iv, AES_ENCRYPTION);
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
    const byte key[AES_KEY_SIZE] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };

    // zeroize the buffers we will use
    memset(decrypted, 0, sizeof(decrypted));
    memset(iv, 0, sizeof(iv));

    // initialize aes 
    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret != 0) return ret;

    // TODO: get the key from global secrets 

    // extract the iv from the buffer
    memcpy(iv, enc_request, AES_IV_SIZE);

    // set the key 
    ret = wc_AesSetKey(&aes, key, AES_KEY_SIZE, iv, AES_DECRYPTION);
    if (ret != 0) return ret;

    // decrypt the data 
    ret = wc_AesCbcDecrypt(&aes, decrypted, enc_request+AES_IV_SIZE, REQUEST_PADDED_SIZE);
    if (ret != 0) return ret;

    wc_AesFree(&aes);

    // deserialize (unpadding not needed because all sizes are constant)
    deserialize_request(decrypted, request);   

    return 0; 
}

