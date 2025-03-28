#include "secure_ipc.h"
#include <stdio.h>
#include <unistd.h>

int main() {
    SecurityConfig config = {
        .encryption_key = {0x01, 0x02 /* ... 32 bytes ... */},
        .authorized_processes = {1001, 1002, 1003},
        .session_token = rand(),
        .use_encryption = true
    };
    printf("Secure IPC Framework\n");
    printf("Config: Encryption=%s, Authorized PIDs={1001,1002,1003}\n", config.use_encryption ? "ON" : "OFF");
    return 0;
}
