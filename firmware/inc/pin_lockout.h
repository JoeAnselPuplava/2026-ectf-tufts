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

void pin_lockout(void);

void wrong_pin_lockout_init(void);