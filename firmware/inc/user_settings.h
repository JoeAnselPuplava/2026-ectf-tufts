#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

/* -------------------------------------------------------------------------
 * Math Configuration
 * ------------------------------------------------------------------------- */
// #define USE_FAST_MATH           // Use the optimized TFM math library
// #define TFM_ECC256              // Optimize strictly for 256-bit curves
// #define FP_MAX_BITS 512         // Max integer size (Shrinks RAM usage)
/* -------------------------------------------------------------------------
 * Math Configuration
 * ------------------------------------------------------------------------- */
#define WOLFSSL_SP
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_ECC
// #define WOLFSSL_SP
// #define WOLFSSL_SP_SMALL             // <-- RESTORED: Keeps memory footprint tiny
// #define WOLFSSL_SMALL_STACK          // <-- RESTORED: Prevents stack overflow crashes

// #define WOLFSSL_SP_MATH_ALL
// #define WOLFSSL_HAVE_SP_ECC
// #define WOLFSSL_SP_ASM               // <-- ADDED: Enables Assembly math
// #define WOLFSSL_SP_ARM_THUMB_ASM     // <-- ADDED: Forces the M0+ Thumb-1 architecture

/* -------------------------------------------------------------------------
 * System & Memory Configuration
 * ------------------------------------------------------------------------- */
#define SINGLE_THREADED         // No OS threads available
#define NO_FILESYSTEM           // No stdio/filesystem available
// #define WOLFSSL_SMALL_STACK     // Favor heap over stack
#define WOLFCRYPT_ONLY          // Build only the crypto (no TLS/SSL)
#define WC_NO_DEFAULT_DEVID     // No default device ID

/* -------------------------------------------------------------------------
 * Algorithm Selection
 * ------------------------------------------------------------------------- */
#define HAVE_ECC                // Enable Elliptic Curves
// #define HAVE_COMP_KEY           // Enable Compressed Keys (0x02/0x03)
#define WOLFSSL_SECP256R1       // Enable NIST P-256 Curve
#define WOLFSSL_SHA256          // Enable SHA-256
#define WOLFSSL_AES_DIRECT      // Enable AES-CBC Direct Access

/* -------------------------------------------------------------------------
 * RNG Configuration (Bypass DRBG entirely)
 * ------------------------------------------------------------------------- */
#define NO_DEV_RANDOM           // No /dev/urandom
#define WC_NO_HASHDRBG          // Disable WolfSSL's software DRBG layer

// Force WolfSSL to call our function directly for ALL random generation
#define CUSTOM_RAND_GENERATE_BLOCK generate_random_bytes

extern int generate_random_bytes(unsigned char* output, unsigned int sz);

#endif /* WOLFSSL_USER_SETTINGS_H */