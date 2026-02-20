#ifndef __BOARD_RANDOM_H__
#define __BOARD_RANDOM_H__

#include <ti/driverlib/dl_trng.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>
#include <host_messaging.h>

int mspm0_trng_seed(byte* output, word32 sz);
// int my_trng_seed_gen(unsigned char* output, unsigned int sz);

#endif //__BOARD_RANDOM_H__