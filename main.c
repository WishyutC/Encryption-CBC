#include <stdio.h>
#include "Encrypt/Encryption.c"

//Read argument in command line
int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: %s [encrypt|decrypt] [Secret_key] [input file] [output file]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "encrypt") == 0) {
        file_encrypt(argv[2], argv[3], argv[4]);
        printf("Encryption completed. Output saved to %s.\n", argv[4]);
    } else if (strcmp(argv[1], "decrypt") == 0) {
        file_decrypt(argv[2], argv[3], argv[4]);
        printf("Decryption completed. Output saved to %s.\n", argv[4]);
    } else {
        printf("Invalid option. Use 'encrypt' or 'decrypt'.\n");
        return 1;
    }   

    return 0;
}