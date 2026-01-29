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
#include <wolfssl/wolfcrypt/sha256.h>

bool check_pin(unsigned char *pin) {
    print_debug("Checking PIN\n");

    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    wc_Sha256 sha;

    /* Initialize SHA-256 */
    if (wc_InitSha256(&sha) != 0) {
        print_error("SHA256 init failed\n");
        return false;
    }

    /* Hash the provided PIN */
    wc_Sha256Update(&sha, pin, (word32)strlen((char *)pin));
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    /* Compare against stored hash */
    if (memcmp(hash, HSM_PIN_HASH, WC_SHA256_DIGEST_SIZE) == 0) {
        print_debug("PIN OK\n");
        return true;
    } else {
        print_error("Invalid PIN\n");
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
    return true;
}
