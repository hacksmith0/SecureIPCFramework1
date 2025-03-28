#include "secure_ipc.h"
#include <sys/shm.h>
#include <semaphore.h>
#include <fcntl.h>

typedef struct {
    int shared_memory_id;
    sem_t* semaphore;
    uint8_t* shared_buffer;
} CoreIPC;

CoreIPC initCoreIPC() {
    CoreIPC ipc;
    ipc.shared_memory_id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0666);
    ipc.shared_buffer = (uint8_t*)shmat(ipc.shared_memory_id, NULL, 0);
    ipc.semaphore = sem_open("ipc_sem", O_CREAT, 0644, 1);
    return ipc;
}

bool sendCoreMessage(CoreIPC* ipc, SecureMessage* msg) {
    sem_wait(ipc->semaphore);
    memcpy(ipc->shared_buffer, msg, sizeof(SecureMessage));
    memcpy(ipc->shared_buffer + sizeof(SecureMessage), msg->encrypted_data, msg->data_length);
    sem_post(ipc->semaphore);
    return true;
}

bool receiveCoreMessage(CoreIPC* ipc, SecureMessage* msg) {
    sem_wait(ipc->semaphore);
    memcpy(msg, ipc->shared_buffer, sizeof(SecureMessage));
    msg->encrypted_data = (uint8_t*)malloc(msg->data_length);
    memcpy(msg->encrypted_data, ipc->shared_buffer + sizeof(SecureMessage), msg->data_length);
    sem_post(ipc->semaphore);
    return true;
}
