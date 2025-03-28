#ifndef SECURE_IPC_H
#define SECURE_IPC_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t encryption_key[32];
    pid_t authorized_processes[10];
    uint32_t session_token;
    bool use_encryption;
} SecurityConfig;

typedef struct {
    uint32_t message_id;
    pid_t sender_pid;
    uint32_t auth_token;
    size_t data_length;
    uint8_t* encrypted_data;
} SecureMessage;

#endif
