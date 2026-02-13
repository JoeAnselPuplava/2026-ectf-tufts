#include <ti/driverlib/dl_trng.h>
#include "random.h"

#define TRNG_TIMEOUT 500000u

static int trng_inited = 0;

static int trng_init_once(void)
{
    if (trng_inited) return 0;
    DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);
    trng_inited = 1;
    return 0;
}

static int trng_wait_capture_ready(void)
{
    for (volatile uint32_t t = 0; t < TRNG_TIMEOUT; t++) {
        if (DL_TRNG_isCaptureReady(TRNG)) return 0;
    }
    return -5;
}

int mspm0_trng_seed(byte* output, word32 sz)
{
    if (!output) return -1;

    trng_init_once();

    word32 generated = 0;
    while (generated < sz) {
        int ret = trng_wait_capture_ready();
        if (ret != 0) return ret;

        uint32_t w = DL_TRNG_getCapture(TRNG);

        // IMPORTANT: replace this mask with the correct one from your SDK
        DL_TRNG_clearInterruptStatus(TRNG, DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);




        for (int i = 0; i < 4 && generated < sz; i++) {
            output[generated++] = (byte)((w >> (8*i)) & 0xFF);
        }
    }

    return 0;
}
