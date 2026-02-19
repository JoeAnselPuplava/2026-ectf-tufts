/**
 * @file commands.c
 * @author Samuel Meyers
 * @brief eCTF command handlers
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "pin_lockout.h"

#define LISTEN_MAX_ATTEMPTS 4

/* IMPORTANT COMPONENTS FROM HSM.c */
// extern file_t hsm_status[MAX_FILE_COUNT];
static file_t current_file;

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief List out the files on the system.
 *      To be utilized by list and interrogate
 *
 *  @param file_list A pointer to the list_response_t variable in
 *      which to store the results
 */
void generate_list_files(list_response_t *file_list) {
    file_list->n_files = 0;
    file_t temp_file;

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Check if the file is in use
        if (is_slot_in_use(i)) {
            read_file(i, &temp_file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = temp_file.group_id;
            strcpy(file_list->metadata[file_list->n_files].name, (char *)&temp_file.name);
            file_list->n_files++;
        }
    }
}

/**********************************************************
 ******************** COMMAND HANDLERS ********************
 **********************************************************/

/** @brief Perform the list operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int list(uint16_t pkt_len, uint8_t *buf) {
    list_command_t *command = (list_command_t*)buf;
    list_response_t file_list;

    memset(&file_list, 0, sizeof(file_list));

    // copy relevant fields into the final struct
    generate_list_files(&file_list);
    
    if (!check_pin(command->pin)) {
        wrong_pin_lockout_init();
        pin_lockout();
        print_error("Invalid pin");
        return -1;
    }

    // write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len;

    read_command_t *command = (read_command_t*)buf;
    read_response_t file_info;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        wrong_pin_lockout_init();
        pin_lockout();
        print_error("Invalid pin");
        return -1;
    }

    memset(&file_info, 0, sizeof(file_info));
    memset(&curr_file, 0, sizeof(curr_file));

    if (read_file(command->slot, &curr_file) < 0) {
        print_error("Failed to read file");
        return -1;
    }

    if (!validate_permission(curr_file.group_id, PERM_READ)) {
        print_error("Invalid permission");
        return -1;
    }

    // Copy name (bounded)
    // If curr_file.name may not be null-terminated, force termination.
    memcpy(file_info.name, curr_file.name, MAX_NAME_SIZE);
    file_info.name[MAX_NAME_SIZE - 1] = '\0';

    // Decrypt contents into response buffer
    uint16_t plain_len = sizeof(file_info.contents);

    int ret = decrypt_file_contents(
        &curr_file,
        curr_file.group_id,
        (const char*)curr_file.name,
        (uint8_t*)file_info.contents,
        &plain_len
    );
    if (ret != 0) {
        print_error("Decrypt failed");
        return -1;
    }
    print_debug("Decrypt successful");
    char dbg[32];
    sprintf(dbg, "Plain length: %lu", (unsigned long)plain_len);
    print_debug(dbg);

    // Send plaintext length
    pkt_len_t length = MAX_NAME_SIZE + plain_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &file_info, length);
    print_debug("Sent read message");

    // optional: zeroize sensitive buffers
    secure_zero(&curr_file, sizeof(curr_file));
    print_debug("Zeroed curr_file");
    // file_info is sent; don’t zeroize it before write_packet
    return 0;
}



/** @brief Perform the write operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    int ret;
    file_t curr_file;

    if (!check_pin(command->pin)) {
        wrong_pin_lockout_init();
        pin_lockout();
        print_error("Invalid pin");
        return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission");
        return -1;
    }

    create_file(
        &curr_file,
        command->group_id,
        command->name,
        command->contents_len,
        command->contents
    );

    // Store the file persistently
    if (write_file(command->slot, &curr_file, command->uuid) < 0) {
        print_error("Error storing file");
        return -1;
    }

    // Success message with an empty body
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
}



static bool has_receive_permission(group_id_t gid) {
    for (uint8_t i = 0; i < MAX_PERMS; i++) {
        if (global_permissions[i].group_id == gid) {
            return global_permissions[i].receive;
        }
    }
    return false;
}

static void send_abort(slot_t slot, group_id_t group, uint8_t reason) {
    receive_abort_t a;
    memset(&a, 0, sizeof(a));
    a.slot = slot;
    a.group = group;
    a.reason = reason;
    write_packet(TRANSFER_INTERFACE, RECEIVE_ABORT_MSG, &a, sizeof(a));
}

int receive(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len;

    receive_command_t *command = (receive_command_t *)buf;

    msg_type_t cmd;
    uint16_t len_recv_msg;

    receive_req_t req;
    receive_challenge_t chal;
    receive_chalresp_t resp;
    receive_response_t recv_resp;

    if (!check_pin(command->pin)) {
        wrong_pin_lockout_init();
        pin_lockout();
        print_error("Invalid pin");
        return -1;
    }

    memset(&req, 0, sizeof(req));
    memset(&chal, 0, sizeof(chal));
    memset(&resp, 0, sizeof(resp));
    memset(&recv_resp, 0, sizeof(recv_resp));

    // 1) Send slot request
    req.slot = command->read_slot;
    write_packet(TRANSFER_INTERFACE, RECEIVE_REQ_MSG, &req, sizeof(req));

    // 2) Read challenge
    len_recv_msg = 0xffff;
    read_packet(TRANSFER_INTERFACE, &cmd, &chal, &len_recv_msg);

    if (cmd == RECEIVE_ABORT_MSG) {
        print_error("RECEIVE: peer aborted");
        return -1;
    }
    if (cmd != RECEIVE_CHAL_MSG) {
        send_abort(command->read_slot, (group_id_t)0xFFFF, RCV_ABORT_GENERIC);
        print_error("RECEIVE: expected challenge");
        return -1;
    }

    if (chal.slot != command->read_slot) {
        send_abort(command->read_slot, (group_id_t)0xFFFF, RCV_ABORT_GENERIC);
        print_error("RECEIVE: challenge slot mismatch");
        return -1;
    }
    if (chal.group_id == (group_id_t)0xFFFF) {
        send_abort(chal.slot, chal.group_id, RCV_ABORT_GENERIC);
        print_error("RECEIVE: invalid slot");
        return -1;
    }

    // 3) Local permission check
    if (!has_receive_permission(chal.group_id)) {
        send_abort(chal.slot, chal.group_id, RCV_ABORT_GENERIC);
        print_error("RECEIVE: no receive permission");
        return -1;
    }

    // 4) Build challenge response (ECC sign TODO)
    resp.slot = chal.slot;
    resp.group_id = chal.group_id;
    memcpy(resp.nonce, chal.nonce, NONCE_SIZE);

    // TODO: ECC SIGN HERE (later)
    resp.sig_len = 0;
    memset(resp.sig, 0, sizeof(resp.sig));

    write_packet(TRANSFER_INTERFACE, RECEIVE_CHALRESP_MSG, &resp, sizeof(resp));

    // 5) Listener sends back the file
    len_recv_msg = 0xffff;
    read_packet(TRANSFER_INTERFACE, &cmd, &recv_resp, &len_recv_msg);

    if (cmd == RECEIVE_ABORT_MSG) {
        print_error("RECEIVE: peer aborted");
        return -1;
    }
    if (cmd != RECEIVE_MSG) {
        send_abort(resp.slot, resp.group_id, RCV_ABORT_GENERIC);
        print_error("RECEIVE: expected file response");
        return -1;
    }

    if (write_file(command->write_slot, &recv_resp.file, recv_resp.uuid) < 0) {
        send_abort(resp.slot, resp.group_id, RCV_ABORT_GENERIC);
        print_error("Writing received file failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    return 0;
}


/** @brief Perform the receive operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    msg_type_t cmd;
    list_response_t final_list_buf;
    uint16_t len_recv_msg;

    // pin check
    if (!check_pin(command->pin)) {
        wrong_pin_lockout_init();
        pin_lockout();
        print_error("Invalid pin");
        return -1;
    }

    // request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, NULL, 0);

    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message
    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg);
    if (cmd != INTERROGATE_MSG) {
        print_error("Opcode mismatch");
        return -1;
    }

    // return the final list to the user
    write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, &final_list_buf, len_recv_msg);
    return 0;
}


/** @brief Perform the listen operation
 *
 * @return 0 upon success. A negative value on error.
*/
int listen(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len; (void)buf;

    uint8_t uart_buf[256];
    msg_type_t cmd;
    pkt_len_t write_length, read_length;

    list_response_t file_list;
    receive_response_t recv_resp;
    const filesystem_entry_t *metadata;

    // RECEIVE handshake state
    bool pending_valid = false;
    slot_t pending_slot = 0;
    group_id_t pending_group = 0;
    uint8_t pending_nonce[NONCE_SIZE];

    for (int attempts = 0; attempts < LISTEN_MAX_ATTEMPTS; attempts++) {
        read_length = sizeof(uart_buf);
        memset(uart_buf, 0, sizeof(uart_buf));

        if (read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length) != MSG_OK) {
            print_error("LISTEN: read_packet failed");
            // Try to notify peer (best-effort)
            send_abort(pending_slot, pending_group, RCV_ABORT_GENERIC);
            return -1;
        }

        switch (cmd) {
            case RECEIVE_ABORT_MSG: {
                // Any abort => stop immediately
                pending_valid = false;
                write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                return 0;
            }

            case INTERROGATE_MSG: {
                // unchanged interrogate behavior
                memset(&file_list, 0, sizeof(file_list));
                generate_list_files(&file_list);

                write_length = LIST_PKT_LEN(file_list.n_files);
                write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list, write_length);

                write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                return 0;
            }

            case RECEIVE_REQ_MSG: {
                receive_req_t *req = (receive_req_t *)uart_buf;
                receive_challenge_t chal;
                file_t temp;

                memset(&chal, 0, sizeof(chal));
                chal.slot = req->slot;

                if (read_file(req->slot, &temp) < 0) {
                    // Abort: invalid slot
                    send_abort(req->slot, (group_id_t)0xFFFF, RCV_ABORT_GENERIC);
                    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                    return 0;
                }

                chal.group_id = temp.group_id;

                // TODO: real RNG later
                for (int i = 0; i < NONCE_SIZE; i++) {
                    chal.nonce[i] = (uint8_t)(i * 31u + (uint8_t)(chal.group_id & 0xFFu));
                }

                pending_valid = true;
                pending_slot = chal.slot;
                pending_group = chal.group_id;
                memcpy(pending_nonce, chal.nonce, NONCE_SIZE);

                write_packet(TRANSFER_INTERFACE, RECEIVE_CHAL_MSG, &chal, sizeof(chal));
                break; // wait for next transfer message
            }

            case RECEIVE_CHALRESP_MSG: {
                receive_chalresp_t *resp = (receive_chalresp_t *)uart_buf;

                if (!pending_valid) {
                    send_abort(resp->slot, resp->group_id, RCV_ABORT_GENERIC);
                    print_error("RECEIVE: no pending challenge");
                    return -1;
                }

                if (resp->slot != pending_slot || resp->group_id != pending_group) {
                    pending_valid = false;
                    send_abort(resp->slot, resp->group_id, RCV_ABORT_GENERIC);
                    print_error("RECEIVE: response mismatch");
                    return -1;
                }

                if (memcmp(resp->nonce, pending_nonce, NONCE_SIZE) != 0) {
                    pending_valid = false;
                    send_abort(resp->slot, resp->group_id, RCV_ABORT_GENERIC);
                    print_error("RECEIVE: nonce mismatch");
                    return -1;
                }

                // TODO: ECC VERIFY HERE (later)
                // If verify fails: send_abort(...) and return.

                pending_valid = false;

                memset(&recv_resp, 0, sizeof(recv_resp));
                if (read_file(resp->slot, &recv_resp.file) < 0) {
                    send_abort(resp->slot, resp->group_id, RCV_ABORT_GENERIC);
                    print_error("Failed to read file");
                    return -1;
                }

                if (recv_resp.file.group_id != resp->group_id) {
                    send_abort(resp->slot, resp->group_id, RCV_ABORT_GENERIC);
                    print_error("RECEIVE: group mismatch");
                    return -1;
                }

                metadata = get_file_metadata(resp->slot);
                if (metadata == NULL) {
                    send_abort(resp->slot, resp->group_id, RCV_ABORT_GENERIC);
                    print_error("Getting metadata failed");
                    return -1;
                }

                memcpy(&recv_resp.uuid, &metadata->uuid, UUID_SIZE);

                write_length = sizeof(receive_response_t);
                write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &recv_resp, write_length);

                write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                return 0;
            }

            default:
                // Unknown message: abort and stop
                send_abort((slot_t)0xFF, (group_id_t)0xFFFF, RCV_ABORT_GENERIC);
                print_error("Bad message type");
                return -1;
        }
    }

    // If we got here, we hit attempts limit without completing handshake.
    send_abort(pending_slot, pending_group, RCV_ABORT_GENERIC);
    print_error("LISTEN: handshake timeout");
    return -1;
}