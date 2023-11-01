#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// The AES key should be exactly 32 bytes (256 bits)
#define AES_KEY_SIZE 32

void generate_key(unsigned char *key) {
    if (RAND_bytes(key, AES_KEY_SIZE) != 1) {
        fprintf(stderr, "Error generating random key\n");
        exit(1);
    }
}

void encrypt_password(const char *password, const unsigned char *key, unsigned char *output) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, AES_KEY_SIZE * 8, &aesKey);
    AES_encrypt((const unsigned char *)password, output, &aesKey);
}

void decrypt_password(const unsigned char *input, const unsigned char *key, char *output) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, AES_KEY_SIZE * 8, &aesKey);
    AES_decrypt(input, (unsigned char *)output, &aesKey);
}

void create_hash(const char *password, const unsigned char *salt, unsigned char *output) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salt, AES_KEY_SIZE);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(output, &sha256);
}

int verify_master_password(const unsigned char *stored_hash, const char *input_password, const unsigned char *salt) {
    unsigned char input_hash[AES_KEY_SIZE];
    create_hash(input_password, salt, input_hash);
    return memcmp(stored_hash, input_hash, AES_KEY_SIZE) == 0;
}

int main() {
    unsigned char master_key[AES_KEY_SIZE];
    generate_key(master_key);

    unsigned char salt[AES_KEY_SIZE];
    RAND_bytes(salt, AES_KEY_SIZE);

    unsigned char stored_hash[AES_KEY_SIZE];
    create_hash("master_password", salt, stored_hash);

    char input_password[256];

    while (1) {
        printf("Enter the master password: ");
        scanf("%s", input_password);

        if (verify_master_password(stored_hash, input_password, salt)) {
            printf("Access granted.\n");
            break;
        } else {
            printf("Access denied. Please try again.\n");
        }
    }

    char service[256];
    char username[256];
    char password[256];
    unsigned char password_key[AES_KEY_SIZE];
    char encrypted_password[256];

    while (1) {
        printf("\nOptions:\n");
        printf("1. Store a new password\n");
        printf("2. Retrieve a stored password\n");
        printf("3. Quit\n");
        printf("Select an option: ");

        int choice;
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter the service or website name: ");
                scanf("%s", service);
                printf("Enter your username: ");
                scanf("%s", username);
                printf("Generate a new secure password? (y/n): ");

                char generate_new_password;
                scanf(" %c", &generate_new_password);

                if (generate_new_password == 'y' || generate_new_password == 'Y') {
                    // Generate a secure random password
                    for (int i = 0; i < AES_KEY_SIZE; i++) {
                        password[i] = (char)(rand() % 256);
                    }
                } else {
                    printf("Enter your password: ");
                    scanf("%s", password);
                }

                generate_key(password_key);
                encrypt_password(password, password_key, encrypted_password);

                FILE *password_file = fopen("passwords.txt", "a");
                fprintf(password_file, "%s %s %s\n", service, username, encrypted_password);
                fclose(password_file);

                printf("Password for %s stored securely.\n", service);
                break;

            case 2:
                printf("Enter the service or website name: ");
                scanf("%s", service);
                printf("Enter your username: ");
                scanf("%s", username);

                FILE *password_file = fopen("passwords.txt", "r");
                char stored_service[256];
                char stored_username[256];
                char stored_encrypted_password[256];
                int found = 0;

                while (fscanf(password_file, "%s %s %s", stored_service, stored_username, stored_encrypted_password) != EOF) {
                    if (strcmp(service, stored_service) == 0 && strcmp(username, stored_username) == 0) {
                        found = 1;

                        decrypt_password(stored_encrypted_password, password_key, password);
                        printf("Password for %s: %s\n", service, password);
                        break;
                    }
                }

                fclose(password_file);

                if (!found) {
                    printf("Password not found.\n");
                }

                break;

            case 3:
                printf("Goodbye!\n");
                return 0;

            default:
                printf("Invalid choice. Please select a valid option.\n");
                break;
        }
    }
}
