#ifndef KSAFE_CRYPTOKIT_BRIDGE_H
#define KSAFE_CRYPTOKIT_BRIDGE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t ksafe_cryptokit_aes_gcm_encrypt(
    const uint8_t *key_pointer,
    int32_t key_count,
    const uint8_t *nonce_pointer,
    int32_t nonce_count,
    const uint8_t *plaintext_pointer,
    int32_t plaintext_count,
    const uint8_t *authenticated_data_pointer,
    int32_t authenticated_data_count,
    uint8_t *ciphertext_output,
    uint8_t *tag_output
);

int32_t ksafe_cryptokit_aes_gcm_decrypt(
    const uint8_t *key_pointer,
    int32_t key_count,
    const uint8_t *nonce_pointer,
    int32_t nonce_count,
    const uint8_t *ciphertext_pointer,
    int32_t ciphertext_count,
    const uint8_t *tag_pointer,
    int32_t tag_count,
    const uint8_t *authenticated_data_pointer,
    int32_t authenticated_data_count,
    uint8_t *plaintext_output
);

#ifdef __cplusplus
}
#endif

#endif
