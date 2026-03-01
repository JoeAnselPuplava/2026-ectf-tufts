/**
 * @file    board_random.c
 * @author  Ming Dynasty
 * @brief   Hardware random number generation for the HSM
 * @date    2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
 */
#include "ti_msp_dl_config.h"
#include "board_random.h"
#include <host_messaging.h>

#define TRNG_TIMEOUT 500000u

static int trng_inited = 0;

/**
 * @brief Internal helper to poll TRNG capture status.
 * @return 0 on success, -5 on timeout.
 */
static int trng_wait_capture_ready(void)
{
    for (volatile uint32_t t = 0; t < TRNG_TIMEOUT; t++) {
        if (DL_TRNG_isCaptureReady(TRNG)) {
            return 0;
        }
    }
    return -5;  // timeout
}

/**
 * @brief Internal hardware initialization. Runs only once.
 * @return 0 on success, -5 on hardware failure.
 */
static int trng_init_once(void)
{
    if (trng_inited)
        return 0;

    // Put TRNG into normal operating mode
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);

    // Discard the first capture
    if (trng_wait_capture_ready() != 0)
        return -5;

    // Clear before reading
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
    (void)DL_TRNG_getCapture(TRNG);

    trng_inited = 1;
    return 0;
}

/**
 * @brief Public interface to retrieve random bytes.
 */
int mspm0_trng_seed(byte* output, word32 sz)
{
    if (!output){
        return -1;}
        
    int ret = trng_init_once();
    if (ret != 0) {
        return ret;
    }
    
    
    word32 generated = 0;
    
    while (generated < sz) {
        
        // Wait for new entropy
        ret = trng_wait_capture_ready();
        if (ret != 0) return ret;

        // Clear before reading
        DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

        // Read the 32-bit random word
        uint32_t w = DL_TRNG_getCapture(TRNG);

        // Extract bytes
        for (int i = 0; i < 4 && generated < sz; i++) {
            output[generated++] = (byte)(w >> (8 * i));
        }
    }

    return 0;
}