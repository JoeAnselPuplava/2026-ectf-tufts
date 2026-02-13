#ifndef __RANDOM_H__
#define __RANDOM_H__

#include <ti/driverlib/dl_trng.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

int mspm0_trng_seed(byte* output, word32 sz);


#endif //__RANDOM_H__