/**
 * @file board_random.h
 * @author Ming Dynasty
 * @brief Hardware random number generation for the HSM
 * @date 2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
 */
#ifndef __BOARD_RANDOM_H__
#define __BOARD_RANDOM_H__

#include <ti/driverlib/dl_trng.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <host_messaging.h>

/**
 * @brief Fills a buffer with entropy using TRNG
 * * @param output Pointer to the buffer to receive random bytes.
 * @param sz     Number of bytes to generate.
 * @return int   0 on success, negative error code on timeout or null pointer.
 */
int mspm0_trng_seed(byte* output, word32 sz);

#endif //__BOARD_RANDOM_H__