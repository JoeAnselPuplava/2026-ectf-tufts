/**
 * @file    pin_lockout.c
 * @author  Ming Dynasty
 * @brief   Lockout mechanism for incorrect PIN attempts
 * @date    2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
 */
#include "pin_lockout.h"
#include "simple_flash.h"
#include "host_messaging.h"

extern uint32_t app2_start;
extern uint32_t app2_end;

// Use them (note: take address of the symbol)
uint32_t *app2_flash_addr = (uint32_t *)&app2_start;

#define LOCKOUT_TIME_PERIODS 3  // 3 seconds
#define LOCKOUT_PERIOD_DURATION 5000000  // ~1 second at 32MHz

/** @brief Waits a pre-detemined amount of time before allowing the user to attempt a new 
*          host commmand after an incorrect pin is entered 
*/
void pin_lockout(void){
    uint32_t curr_lockout_time;
    
    // Read the current lockout time from flash
    flash_simple_read((uint32_t)app2_flash_addr, &curr_lockout_time, sizeof(curr_lockout_time));
    
    while (curr_lockout_time > 0) {
        
        // wait 1 second
        for (volatile uint32_t i = 0; i < LOCKOUT_PERIOD_DURATION; i++);
        
        curr_lockout_time--;
        
        // Erase and write updated lockout time
        flash_simple_erase_page((uint32_t)app2_flash_addr);
        flash_simple_write((uint32_t)app2_flash_addr, &curr_lockout_time, sizeof(curr_lockout_time));
    }
}

/** @brief Handles flash memory maintenance for pin lockout
*/
void wrong_pin_lockout_init(void) {
    uint32_t lockout_time = LOCKOUT_TIME_PERIODS;
    flash_simple_erase_page((uint32_t)app2_flash_addr);
    flash_simple_write((uint32_t)app2_flash_addr, &lockout_time, sizeof(lockout_time));
}