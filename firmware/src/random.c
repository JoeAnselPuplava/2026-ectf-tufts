#include "ti_msp_dl_config.h"
#include "random.h"

#define TRNG_TIMEOUT 500000u

static int trng_inited = 0;

static int trng_wait_capture_ready(void)
{
    for (volatile uint32_t t = 0; t < TRNG_TIMEOUT; t++) {
        if (DL_TRNG_isCaptureReady(TRNG)) {
            return 0;
        }
    }
    return -5;  // timeout
}

static int trng_init_once(void)
{
    if (trng_inited)
        return 0;

    /* Put TRNG into normal operating mode */
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);

    /* Discard the first capture (TI recommends this) */
    if (trng_wait_capture_ready() != 0)
        return -5;

    /* Clear BEFORE reading */
    DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
    (void)DL_TRNG_getCapture(TRNG);

    trng_inited = 1;
    return 0;
}

int mspm0_trng_seed(byte* output, word32 sz)
{
    if (!output)
        return -1;

    int ret = trng_init_once();
    if (ret != 0) {
        //print_error("TRNG normal func failed\n");
        return ret;
    }
        

    word32 generated = 0;

    while (generated < sz) {

        /* Wait for new entropy */
        ret = trng_wait_capture_ready();
        if (ret != 0)
            return ret;

        /* Clear BEFORE reading */
        DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

        /* Read the 32-bit random word */
        uint32_t w = DL_TRNG_getCapture(TRNG);

        /* Extract bytes */
        for (int i = 0; i < 4 && generated < sz; i++) {
            output[generated++] = (byte)((w >> (8 * i)) & 0xFF);
        }

        /* Some MSPM0 variants require retriggering */
        //DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_GEN_RANDOM);
    }

    return 0;
}
