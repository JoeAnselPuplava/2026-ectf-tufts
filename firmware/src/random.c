#include "random.h"

/**
 * wc_GenerateSeed() for MSPM0L2228
 * Fills the output buffer with hardware entropy from the TRNG peripheral.
 */
int mspm0_trng_seed(byte* output, word32 sz)
{
// int wc_GenerateSeed(byte* output, word32 sz) // Change from 3 args to 2
// {

    if (output == NULL) {
        return -1;
    }

    /* 1. Reset and Enable the TRNG Peripheral */
    /* Note: In a full application, you usually call DL_TRNG_init() in your
       system initialization code (ti_msp_dl_config.c). */
    DL_TRNG_reset(TRNG);
    DL_TRNG_enablePower(TRNG);
    
    /* Optional: Configure TRNG for your specific needs. 
       Default settings are usually sufficient for eCTF. */

    word32 generated = 0;
    while (generated < sz) {
        /* 2. Command the TRNG to capture new entropy */
        DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_TEST_ANA);

        /* 3. Wait for the hardware to finish the capture */
        while (DL_TRNG_getCurrentState(TRNG) & DL_TRNG_STATE_OFF);

        /* 4. Retrieve the random data (TRNG returns a 32-bit word) */
        uint32_t randomWord = DL_TRNG_getCapture(TRNG);

        /* 5. Copy bytes into the output buffer */
        for (int i = 0; i < 4 && generated < sz; i++) {
            output[generated++] = (byte)((randomWord >> (i * 8)) & 0xFF);
        }
    }

    return 0;
}