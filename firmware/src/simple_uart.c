/**
 * @file "simple_uart.c"
 * @author Ming Dynasty
 * @brief UART Interrupt Handler Implementation
 * @date 2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
 */

#include "simple_uart.h"

/**********************************************************
 *************** HARDWARE ABSTRACTIONS ********************
 **********************************************************/

// This holds the two UART configurations necessary for communication
UART_Regs *uart_inst[] = {UART_0_INST, UART_1_INST};

UART_Regs *get_uart_handle(int uart_id) {
    if (uart_id >= 0 && uart_id < CONFIG_UART_COUNT) {
        return uart_inst[uart_id];
    }
    else {
        return uart_inst[uart_id];
    }
}

/** @brief Reads the next available character from UART.
 *
 *  @param uart_id The index of UART to use
 *  @return The character read.
*/
int uart_readbyte(int uart_id){
    uint8_t data = DL_UART_receiveDataBlocking(get_uart_handle(uart_id));
    return data;
}

/** @brief Writes a byte to UART.
 *
 *  @param uart_id The index of UART to use
 *  @param data The byte to be written.
*/
void uart_writebyte(int uart_id, uint8_t data) {
    DL_UART_transmitDataBlocking(get_uart_handle(uart_id), data);
}

