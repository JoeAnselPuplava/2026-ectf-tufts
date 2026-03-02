/**
 * @file pin_lockout.h
 * @author Ming Dynasty
 * @brief Lockout mechanism for incorrect PIN attempts
 * @date 2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
 */
#pragma once

#include <stdint.h>

/** @brief Waits a pre-detemined amount of time before allowing the user to attempt a new 
*          host commmand after an incorrect pin is entered 
*/
void pin_lockout(void);

/** @brief Handles flash memory maintenance for pin lockout
*/
void wrong_pin_lockout_init(void);