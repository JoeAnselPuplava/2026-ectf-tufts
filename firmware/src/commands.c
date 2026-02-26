/**
 * @file commands.c
 * @author Ming Dynasty
 * @brief eCTF command handlers
 * @date 2026
 *
 * @copyright Copyright (c) 2026 Tufts University. All rights reserved.
 */

#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "pin_lockout.h"

// This union ensures we only ever use 8KB of RAM instead of 16KB
// static file_t shared_file __attribute__((aligned(8)));
// static receive_response_t shared_recv_resp __attribute__((aligned(8)));
// static read_response_t shared_read_resp __attribute__((aligned(8)));
typedef union {
    file_t file;
    read_response_t read_resp;
    receive_response_t recv_resp;
} shared_workspace_t;

static shared_workspace_t workspace __attribute__((aligned(8)));
#define LISTEN_MAX_ATTEMPTS 4



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

    // Loop through all files on the system
    for (uint8_t i = 0; i < MAX_FILE_COUNT; i++) {
        // Check if the file is in use
        if (is_slot_in_use(i)) {
            // THE FIX: Use the global buffer instead of a local variable
            read_file(i, &workspace.file);

            file_list->metadata[file_list->n_files].slot = i;
            file_list->metadata[file_list->n_files].group_id = workspace.file.group_id;
            strcpy(file_list->metadata[file_list->n_files].name, (char *)&workspace.file.name);
            file_list->n_files++;
        }
    }
    // Clean up when done
    secure_zero(&workspace.file, sizeof(workspace.file)); 
}

void validate_list_files(list_response_t *file_list, list_response_t *validated_file_list, interrogate_request_t *perms) {
    validated_file_list->n_files = 0; 

    for (uint8_t i = 0; i < file_list->n_files; i++) {
        for (uint8_t j = 0; j < MAX_PERMS; j++) { // TODO: replace MAX_PERMS with perm size if time cutdown needed 
            if (file_list->metadata[i].group_id == perms->permissions[j].group_id) {
                // verify that requesting HSM has receive permission 
                if (perms->permissions[j].receive) {
                    validated_file_list->metadata[validated_file_list->n_files].slot = file_list->metadata[i].slot;
                    validated_file_list->metadata[validated_file_list->n_files].group_id = file_list->metadata[i].group_id;
                    strcpy(validated_file_list->metadata[validated_file_list->n_files].name, file_list->metadata[i].name); // TODO: come replace strcpy
                    validated_file_list->n_files++; 
                }
            }
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

    print_debug("In list function\n");
    // write success packet with list
    pkt_len_t length = LIST_PKT_LEN(file_list.n_files);
    write_packet(CONTROL_INTERFACE, LIST_MSG, &file_list, length);
    return 0;
}


/** @brief Perform the read operation
 *
 * @param pkt_len The length of the incoming packet
 * @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int read(uint16_t pkt_len, uint8_t *buf) {
    (void)pkt_len;
    print_debug("READING A FILE");
    
    read_command_t *command = (read_command_t*)buf;
    
    if (!check_pin(command->pin)) {
        wrong_pin_lockout_init(); pin_lockout(); print_error("Invalid pin"); return -1;
    }

    memset(&workspace, 0, sizeof(workspace));

    if (read_file(command->slot, &workspace.file) < 0) {
        print_error("Failed to read file"); return -1;
    }

    if (!validate_permission(workspace.file.group_id, PERM_READ)) {
        print_error("Invalid permission"); return -1;
    }

    // 1. Save data before we overwrite the union
    uint16_t group_id = workspace.file.group_id;
    char temp_name[MAX_NAME_SIZE];
    memcpy(temp_name, workspace.file.name, MAX_NAME_SIZE);
    temp_name[MAX_NAME_SIZE - 1] = '\0';

    uint16_t plain_len = MAX_CONTENTS_SIZE;

    // 2. Decrypt in-place. 
    int ret = decrypt_file_contents(
        &workspace.file,
        group_id,
        temp_name,
        (uint8_t*)workspace.read_resp.contents, 
        &plain_len
    );
    
    if (ret != 0) {
        print_error("Decrypt failed");
        secure_zero(&workspace, sizeof(workspace)); 
        return -1;
    }
    
    // 3. Assemble the perfectly aligned header at the top of the union
    memcpy(workspace.read_resp.name, temp_name, MAX_NAME_SIZE);

    pkt_len_t length = MAX_NAME_SIZE + plain_len;
    write_packet(CONTROL_INTERFACE, READ_MSG, &workspace.read_resp, length);
    print_debug("Sent read message");

    secure_zero(&workspace, sizeof(workspace));
    return 0;
}



/** @brief Perform the write operation
 *
 * @param pkt_len The length of the incoming packet
 * @param buf A pointer the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
*/
int write(uint16_t pkt_len, uint8_t *buf) {
    write_command_t *command = (write_command_t*)buf;
    memset(&workspace, 0, sizeof(workspace));

    if (!check_pin(command->pin)) {
        wrong_pin_lockout_init(); pin_lockout(); print_error("Invalid pin"); return -1;
    }

    if (!validate_permission(command->group_id, PERM_WRITE)) {
        print_error("Invalid permission"); return -1;
    }

    if (create_file(&workspace.file, command->group_id, command->name, command->contents_len, command->contents) != 0) {
        print_error("Error creating file");
        secure_zero(&workspace, sizeof(workspace)); return -1;
    }

    if (write_file(command->slot, &workspace.file, command->uuid) < 0) {
        print_error("Error storing file");
        secure_zero(&workspace, sizeof(workspace)); return -1;
    }

    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    secure_zero(&workspace, sizeof(workspace));
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
    
    // THE FIX: Removed local receive_response_t recv_resp!

    if (!check_pin(command->pin)) {
        wrong_pin_lockout_init();
        pin_lockout();
        print_error("Invalid pin");
        return -1;
    }

    memset(&req, 0, sizeof(req));
    memset(&chal, 0, sizeof(chal));
    memset(&resp, 0, sizeof(resp));
    memset(&workspace, 0, sizeof(workspace)); // Clean workspace

    // 1) Send slot request
    req.slot = command->read_slot;
    write_packet(TRANSFER_INTERFACE, RECEIVE_REQ_MSG, &req, sizeof(req));

    // 2) Read challenge
    len_recv_msg = 0;
    read_packet(TRANSFER_INTERFACE, &cmd, &chal, &len_recv_msg, sizeof(chal));

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
    len_recv_msg = 0x0;
    
    // THE FIX: Read directly into the workspace union
    read_packet(TRANSFER_INTERFACE, &cmd, &workspace.recv_resp, &len_recv_msg, sizeof(workspace.recv_resp));

    if (cmd == RECEIVE_ABORT_MSG) {
        print_error("RECEIVE: peer aborted");
        return -1;
    }
    if (cmd != RECEIVE_MSG) {
        send_abort(resp.slot, resp.group_id, RCV_ABORT_GENERIC);
        print_error("RECEIVE: expected file response");
        return -1;
    }

    // THE FIX: Write the file from the workspace union
    if (write_file(command->write_slot, &workspace.recv_resp.file, workspace.recv_resp.uuid) < 0) {
        send_abort(resp.slot, resp.group_id, RCV_ABORT_GENERIC);
        print_error("Writing received file failed");
        return -1;
    }

    write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
    secure_zero(&workspace, sizeof(workspace));
    return 0;
}


/** @brief Perform the interrogate operation
 *
 *  @param pkt_len The length of the incoming packet
 *  @param buf A pointer to the incoming message buffer
 *
 * @return 0 upon success. A negative value on error.
 */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
    interrogate_command_t *command = (interrogate_command_t*)buf;
    interrogate_request_t request; 
    uint8_t *enc_request[AES_IV_SIZE + REQUEST_PADDED_SIZE]; 
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

    // zeroize the buffers we will use
    memset(&request, 0, sizeof(request));
    memset(enc_request, 0, sizeof(enc_request));

    // gather all permissions 
    memcpy(&request.permissions, &global_permissions, sizeof(group_permission_t) * MAX_PERMS);

    // encrypt perms 
    encrypt_perms(&request, enc_request);

    // request the file list from the neighboring device
    write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, enc_request, ((AES_IV_SIZE + REQUEST_PADDED_SIZE) * sizeof(uint8_t)));

    // set essentially no limit to the receive message size
    len_recv_msg = 0xffff;

    // recieve the response message

    read_packet(TRANSFER_INTERFACE, &cmd, &final_list_buf, &len_recv_msg, sizeof(final_list_buf));
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

    interrogate_request_t inter_req; 
    uint8_t *enc_request[AES_IV_SIZE + REQUEST_PADDED_SIZE];
    list_response_t file_list;
    list_response_t validated_file_list; 

    const filesystem_entry_t *metadata;
    
    // THE FIX: Removed local receive_response_t recv_resp!

    // RECEIVE handshake state
    bool pending_valid = false;
    slot_t pending_slot = 0;
    group_id_t pending_group = 0;
    uint8_t pending_nonce[NONCE_SIZE];

    for (int attempts = 0; attempts < LISTEN_MAX_ATTEMPTS; attempts++) {
        read_length = sizeof(uart_buf);
        memset(uart_buf, 0, sizeof(uart_buf));

        if (read_packet(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length, sizeof(uart_buf)) != MSG_OK) {
            print_error("LISTEN: read_packet failed");
            send_abort(pending_slot, pending_group, RCV_ABORT_GENERIC);
            return -1;
        }

        switch (cmd) {
            case RECEIVE_ABORT_MSG: {
                pending_valid = false;
                write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                return 0;
            }

            case INTERROGATE_MSG: {
                // zeroize the buffers we will use
                memset(&inter_req, 0, sizeof(inter_req));
                memset(enc_request, 0, sizeof(enc_request));

                // get the request 
                // enc_request = (uint8_t *)uart_buf; 
                memcpy(enc_request, (uint8_t *)uart_buf, sizeof(enc_request));
                decrypt_perms(&inter_req, enc_request);

                // zeroize the buffers we will use
                memset(&file_list, 0, sizeof(file_list));
                memset(&validated_file_list, 0, sizeof(validated_file_list));

                // generate a list of files for the other device
                generate_list_files(&file_list);

                // check every file against the provided permission list on return only files with receive perms 
                validate_list_files(&file_list, &validated_file_list, &inter_req);

                // send the list of files on this device
                write_length = LIST_PKT_LEN(validated_file_list.n_files);
                write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &validated_file_list, write_length);
                write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                return 0;
            }

            case RECEIVE_REQ_MSG: {
                receive_req_t *req = (receive_req_t *)uart_buf;
                receive_challenge_t chal;

                memset(&chal, 0, sizeof(chal));
                chal.slot = req->slot;
                memset(&workspace, 0, sizeof(workspace));

                // Use workspace.file to check the slot safely
                if (read_file(req->slot, &workspace.file) < 0) {
                    send_abort(req->slot, (group_id_t)0xFFFF, RCV_ABORT_GENERIC);
                    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                    return 0;
                }

                chal.group_id = workspace.file.group_id;

                // Use the PRNG to generate a secure random nonce
                if (generate_random_bytes(chal.nonce, NONCE_SIZE) != 0) {
                    send_abort(req->slot, chal.group_id, RCV_ABORT_GENERIC);
                    write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                    secure_zero(&workspace, sizeof(workspace));
                    return 0;
                }

                pending_valid = true;
                pending_slot = chal.slot;
                pending_group = chal.group_id;
                memcpy(pending_nonce, chal.nonce, NONCE_SIZE);

                write_packet(TRANSFER_INTERFACE, RECEIVE_CHAL_MSG, &chal, sizeof(chal));
                
                // Clean up workspace before breaking to next message
                secure_zero(&workspace, sizeof(workspace));
                break; 
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

                // Verify the ECDSA signature against the pending nonce
                if (check_signature(resp->group_id, pending_nonce, NONCE_SIZE, resp->sig, resp->sig_len) != 0) {
                    pending_valid = false;
                    send_abort(resp->slot, resp->group_id, RCV_ABORT_GENERIC);
                    print_error("RECEIVE: invalid signature");
                    return -1;
                }

                pending_valid = false;

                // Use workspace.recv_resp to assemble the packet
                memset(&workspace, 0, sizeof(workspace));
                
                if (read_file(resp->slot, &workspace.recv_resp.file) < 0) {
                    send_abort(resp->slot, resp->group_id, RCV_ABORT_GENERIC);
                    print_error("Failed to read file");
                    return -1;
                }

                if (workspace.recv_resp.file.group_id != resp->group_id) {
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

                memcpy(&workspace.recv_resp.uuid, &metadata->uuid, UUID_SIZE);

                write_length = sizeof(receive_response_t);
                write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &workspace.recv_resp, write_length);

                write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
                
                // Clean up workspace before exiting
                secure_zero(&workspace, sizeof(workspace));
                return 0;
            }

            default:
                send_abort((slot_t)0xFF, (group_id_t)0xFFFF, RCV_ABORT_GENERIC);
                print_error("Bad message type");
                return -1;
        }
    }

    send_abort(pending_slot, pending_group, RCV_ABORT_GENERIC);
    print_error("LISTEN: handshake timeout");
    return -1;
}