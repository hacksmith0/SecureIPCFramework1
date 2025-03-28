#include "secure_ipc.h"
#include <stdlib.h>
#include <string.h>

typedef struct { uint8_t dummy_key[32]; } AES_ctx;
void AES_init_ctx(AES_ctx* ctx, const uint8_t* key) { memcpy(ctx->dummy_key, key, 32); }
void AES_CBC_encrypt_buffer(AES_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len) { memcpy(out, in, len); }
void AES_CBC_decrypt_buffer(AES_ctx* ctx, const uint8_t* in, uint8_t* out, size_t len) { memcpy(out, in, len); }

typedef struct {
    SecurityConfig config;
    AES_ctx aes_context;
} SecurityLayer;

SecurityLayer initSecurityLayer(const SecurityConfig* config) {
    SecurityLayer sec;
    sec.config = *config;
    AES_init_ctx(&sec.aes_context, config->encryption_key);
    return sec;
}

uint32_t authenticate(SecurityLayer* sec, pid_t pid) {
    for (int i = 0; i < 10 && sec->config.authorized_processes[i] != 0; i++) {
        if (sec->config.authorized_processes[i] == pid) return rand();
    }
    return 0;
}

bool encryptMessage(SecurityLayer* sec, SecureMessage* msg, const uint8_t* plaintext) {
    msg->encrypted_data = (uint8_t*)malloc(msg->data_length);
    AES_CBC_encrypt_buffer(&sec->aes_context, plaintext, msg->encrypted_data, msg->data_length);
    return true;
}

bool decryptMessage(SecurityLayer* sec, SecureMessage* msg, uint8_t* plaintext) {
    AES_CBC_decrypt_buffer(&sec->aes_context, msg->encrypted_data, plaintext, msg->data_length);
    return true;
}
