#include "secure_ipc.h"
#include "core_ipc.c"
#include "security.c"
#include <stdio.h>
#include <unistd.h>

typedef struct {
    CoreIPC core;
    SecurityLayer sec;
} SecureIPC;

SecureIPC initSecureIPC(const SecurityConfig* config) {
    SecureIPC ipc;
    ipc.core = initCoreIPC();
    ipc.sec = initSecurityLayer(config);
    return ipc;
}

bool sendMessage(SecureIPC* ipc, pid_t target_pid, const uint8_t* data, size_t length) {
    SecureMessage msg = { .message_id = rand(), .sender_pid = getpid(), .data_length = length };
    msg.auth_token = authenticate(&ipc->sec, msg.sender_pid);
    if (msg.auth_token == 0) return false;
    if (ipc->sec.config.use_encryption) encryptMessage(&ipc->sec, &msg, data);
    else { msg.encrypted_data = (uint8_t*)malloc(length); memcpy(msg.encrypted_data, data, length); }
    bool result = sendCoreMessage(&ipc->core, &msg);
    free(msg.encrypted_data);
    return result;
}

bool receiveMessage(SecureIPC* ipc, uint8_t* buffer) {
    SecureMessage msg;
    if (!receiveCoreMessage(&ipc->core, &msg)) return false;
    if (authenticate(&ipc->sec, msg.sender_pid) != msg.auth_token) { free(msg.encrypted_data); return false; }
    if (ipc->sec.config.use_encryption) decryptMessage(&ipc->sec, &msg, buffer);
    else memcpy(buffer, msg.encrypted_data, msg.data_length);
    free(msg.encrypted_data);
    return true;
}

int main() {
    SecurityConfig config = {
        .encryption_key = {0x01, 0x02 /* ... 32 bytes ... */},
        .authorized_processes = {1001, 1002, 1003},
        .session_token = rand(),
        .use_encryption = true
    };
    SecureIPC ipc = initSecureIPC(&config);
    pid_t pid = getpid();

    if (fork() == 0) {
        uint8_t data[] = "Secure message";
        printf("Sender (PID %d): Sending...\n", getpid());
        sendMessage(&ipc, 1002, data, sizeof(data)) ? printf("Sent successfully\n") : printf("Send failed\n");
        exit(0);
    }

    sleep(1);
    uint8_t buffer[128] = {0};
    printf("Receiver (PID %d): Receiving...\n", pid);
    receiveMessage(&ipc, buffer) ? printf("Received: %s\n", buffer) : printf("Receive failed\n");

    shmdt(ipc.core.shared_buffer);
    shmctl(ipc.core.shared_memory_id, IPC_RMID, NULL);
    sem_close(ipc.core.semaphore);
    sem_unlink("ipc_sem");
    return 0;
}
