#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* -------------------------------------------------------------------------
 * System & Memory Configuration
 * ------------------------------------------------------------------------- */
#define SINGLE_THREADED         // No OS threads available
#define NO_FILESYSTEM           // No stdio/filesystem available
#define WOLFCRYPT_ONLY          // Build only the crypto (no TLS/SSL)
#define WC_NO_DEFAULT_DEVID     // No default device ID

/*
 * FOR TIMING BUT MAY BE TOO SLOW AND NEED TO TEST
 */
// #define ECC_TIMING_RESISTANT

/*
 * TO SUPRESS WARNING
 */
#define USE_WOLF_STRCASECMP
/* -------------------------------------------------------------------------
 * Aggressive Size Reductions (Crucial for Cortex-M0+)
 * ------------------------------------------------------------------------- */
#define NO_ERROR_STRINGS        // Strips out thousands of bytes of error text from .rodata
// #define NO_ASN                  // Disables ASN.1 cert parsing (not needed for raw ECC)
// #define USE_AES_SMALL           // Shrinks AES T-tables in .rodata
// #define WOLFSSL_SMALL_STACK     // Prevents stack overflow crashes in deep crypto calls

/* Disable unused legacy algorithms compiled by default */
#define NO_RSA
#define NO_DSA
#define NO_MD5
#define NO_SHA
#define NO_DES3
#define NO_RC4
#define NO_RABBIT

/* -------------------------------------------------------------------------
 * Math Configuration
 * ------------------------------------------------------------------------- */
#define WOLFSSL_SP              // Enable Single Precision math
#define WOLFSSL_HAVE_SP_ECC     // Use SP for Elliptic Curve
#define WOLFSSL_SP_MATH         // Use C SP math (replaces WOLFSSL_SP_MATH_ALL)
#define WOLFSSL_SP_256          // STRICTLY compile 256-bit math only

/* -------------------------------------------------------------------------
 * Algorithm Selection
 * ------------------------------------------------------------------------- */
#define HAVE_ECC                // Enable Elliptic Curves
#define WOLFSSL_SECP256R1       // Enable NIST P-256 Curve
#define WOLFSSL_SHA256          // Enable SHA-256
#define WOLFSSL_AES_DIRECT      // Enable AES-CBC Direct Access
#define WOLFSSL_CMAC            // Enable CMAC for challenges

/* -------------------------------------------------------------------------
 * RNG Configuration (Bypass DRBG entirely)
 * ------------------------------------------------------------------------- */
#define NO_DEV_RANDOM           // No /dev/urandom
#define WC_NO_HASHDRBG          // Disable WolfSSL's software DRBG layer

// Force WolfSSL to call our function directly for ALL random generation
#define CUSTOM_RAND_GENERATE_BLOCK generate_random_bytes

extern int generate_random_bytes(unsigned char* output, unsigned int sz);

extern int _sp_mulmod(void* r, const void* a, const void* m, void* t);

#endif /* WOLFSSL_USER_SETTINGS_H */