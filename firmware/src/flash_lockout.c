/**
 * @file flash_lockout.c
 * @brief Persistent lockout mechanism to slow repeated attack attempts
 */

#include "lockout.h"
#include "util.h"

#include <flc.h>
#include <mxc_delay.h>
#include <stdint.h>

/* Flash-backed counter symbol (zero-initialized by linker) */
extern uint32_t lockout_counter;
#define LOCKOUT_FLASH_ADDR ((uint32_t)&lockout_counter)

/* Maximum lockout duration (in periods) */
#define LOCKOUT_MAX_PERIODS 60

/* Length of one lockout period in microseconds */
#define LOCKOUT_PERIOD_US 100000

/* Write a new counter value to flash */
static void write_lockout_counter(uint32_t value) {
    UTIL_ASSERT(MXC_FLC_PageErase(LOCKOUT_FLASH_ADDR) == E_NO_ERROR);
    UTIL_ASSERT(
        MXC_FLC_Write(LOCKOUT_FLASH_ADDR, sizeof(value), &value) == E_NO_ERROR
    );
}

/* Resume any pending lockout delay stored in flash */
void lockout_process(void) {
    uint32_t remaining = lockout_counter;

    /* Clamp unexpected values (e.g., power glitch or fault injection) */
    if (remaining > LOCKOUT_MAX_PERIODS) {
        remaining = LOCKOUT_MAX_PERIODS;
        write_lockout_counter(remaining);
    }

    /* Enforce delay and persist progress */
    while (remaining > 0) {
        MXC_Delay(LOCKOUT_PERIOD_US);
        remaining--;
        write_lockout_counter(remaining);
    }

    /* Ensure clean terminal state */
    write_lockout_counter(0);
}

/* Trigger a full lockout delay that survives resets */
void attack_detected(void) {
    write_lockout_counter(LOCKOUT_MAX_PERIODS);
    lockout_process();
}
