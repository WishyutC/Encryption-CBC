#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFFER_SIZE 1024

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); 
    int len, ciphertext_len;

    if (!ctx)
        handle_errors();

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handle_errors();

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        handle_errors();
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handle_errors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    if (!ctx)
        handle_errors();

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
        handle_errors();

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        handle_errors();
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handle_errors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void file_encrypt(const char* user_key, const char* input_file, const char* output_file) {
    FILE *in_file = fopen(input_file, "rb");
    FILE *out_file = fopen(output_file, "wb+");
    unsigned char key[AES_256_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char buffer[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE + AES_BLOCK_SIZE];
    size_t bytes_read;//size of it
    int ciphertext_len;

    //error handling
    if (!in_file || !out_file) {
        perror("File error");
        exit(1);
    }

    // Derive a 32-byte key from the user-provided key (simple example, not secure)
    memset(key, 0, AES_256_KEY_SIZE);
    strncpy((char *)key, user_key, AES_256_KEY_SIZE);

    // Generate a random IV and write it to the output file
    if (!RAND_bytes(iv, AES_BLOCK_SIZE))
        handle_errors();
    fwrite(iv, 1, AES_BLOCK_SIZE, out_file);

    // Write ciphertext to target file until have nothing left
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in_file)) > 0) {
        ciphertext_len = encrypt(buffer, bytes_read, key, iv, ciphertext);
        fwrite(ciphertext, 1, ciphertext_len, out_file);
    }

    fclose(in_file);
    fclose(out_file);
}

void file_decrypt(const char* user_key, const char* input_file, const char* output_file) {
    FILE *in_file = fopen(input_file, "rb");
    FILE *out_file = fopen(output_file, "wb+");
    unsigned char key[AES_256_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char buffer[BUFFER_SIZE + AES_BLOCK_SIZE];
    unsigned char plaintext[BUFFER_SIZE];
    size_t bytes_read;//size of it
    int plaintext_len;

    if (!in_file || !out_file) {
        perror("File error");
        exit(1);
    }

    // Derive a 32-byte key from the user-provided key (simple example, not secure)
    memset(key, 0, AES_256_KEY_SIZE);
    strncpy((char *)key, user_key, AES_256_KEY_SIZE);

    // Read the IV from the input file
    fread(iv, 1, AES_BLOCK_SIZE, in_file);

    // Write plaintext to target file until have nothing left
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), in_file)) > 0) {
        plaintext_len = decrypt(buffer, bytes_read, key, iv, plaintext);
        fwrite(plaintext, 1, plaintext_len, out_file);
    }

    fclose(in_file);
    fclose(out_file);
}


