/**
 * @file    HSM.c
 * @author  Ming Dynasty
 * @brief   Boot code and main function for the HSM
 * @date    2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"
#include "pin_lockout.h"

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/


/** @brief Initializes peripherals for system boot.
*/
void init() {
    // Initialize all of the hardware components
    SYSCFG_DL_init();

    init_fs();
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    int ret = 0;
    uint16_t pkt_len;

    // initialize the device
    init();

    // process commands forever
    while (1) {
        ret = 0;
        
        STATUS_LED_ON();
        secure_zero(uart_buf, sizeof(uart_buf));
        pkt_len = 0;
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len, sizeof(uart_buf));

        if (result != MSG_OK) {
            switch (result)
            {
            case MSG_BAD_PTR:
                print_error("Bad cmd pointer\n");
                break;
            case MSG_NO_ACK:
                print_error("Failed to receive ACK from host\n");
                break;
            case MSG_BAD_LEN:
                print_error("Received bad length\n");
                break;
            default:
                print_error("Failed to receive cmd from host\n");
                break;
            }
            continue;
        }

        // Handle the requested command
        switch (cmd) {
        // Handle list command
        case LIST_MSG:
            ret = list(pkt_len, uart_buf);
            break;

        // Handle read command
        case READ_MSG:
            ret = read(pkt_len, uart_buf);
            break;

        // Handle write command
        case WRITE_MSG:
            ret = write(pkt_len, uart_buf);
            break;

        // Handle receive command
        case RECEIVE_MSG:
            ret = receive(pkt_len, uart_buf);
            break;

        // Handle interrogate command
        case INTERROGATE_MSG:
            ret = interrogate(pkt_len, uart_buf);
            break;

        // Handle listen command
        case LISTEN_MSG:
            ret = listen(pkt_len, uart_buf);
            break;

        // Handle bad command
        default:
            print_error("ERROR");
            break;
        }
        if (ret != 0) {
            print_error("ERROR");
        }
    }
}
