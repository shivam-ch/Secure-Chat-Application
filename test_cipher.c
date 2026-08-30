#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_LONG_TEXT 10000


/* ============================================
   XOR ENCRYPTION / DECRYPTION
   Same function is used for both because:

   Plaintext XOR Key = Ciphertext
   Ciphertext XOR Key = Plaintext
   ============================================ */

void xor_crypt(unsigned char *data, size_t len, const char *key)
{
    size_t key_len = strlen(key);

    if (key_len == 0)
        return;

    for (size_t i = 0; i < len; i++)
    {
        data[i] ^= key[i % key_len];
    }
}


/* ============================================
   PRINT DATA AS HEX

   This allows us to see encrypted bytes even
   if they contain non-printable characters.
   ============================================ */

void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }

    printf("\n");
}


/* ============================================
   TEST FUNCTION
   ============================================ */

void run_test(const char *test_name,
              const unsigned char *original,
              size_t length,
              const char *key)
{
    printf("\n========================================\n");
    printf("TEST: %s\n", test_name);
    printf("========================================\n");

    printf("Key: %s\n", key);
    printf("Original length: %zu bytes\n", length);


    /* Allocate memory */

    unsigned char *data = malloc(length + 1);

    if (data == NULL)
    {
        printf("Memory allocation failed!\n");
        return;
    }


    /* Copy original data */

    if (length > 0)
    {
        memcpy(data, original, length);
    }

    data[length] = '\0';


    /* Show original */

    printf("\nOriginal data:\n");

    if (length == 0)
    {
        printf("[EMPTY STRING]\n");
    }
    else
    {
        printf("%s\n", data);
    }


    /* ========================================
       ENCRYPT
       ======================================== */

    xor_crypt(data, length, key);


    printf("\nEncrypted data (HEX):\n");
    print_hex(data, length);


    /*
     * Verify that ciphertext is different
     * from original for non-empty input.
     */


    /* ========================================
       DECRYPT
       ======================================== */

    xor_crypt(data, length, key);


    printf("\nDecrypted data:\n");

    if (length == 0)
    {
        printf("[EMPTY STRING]\n");
    }
    else
    {
        printf("%s\n", data);
    }


    /* ========================================
       VERIFY ROUND TRIP
       ======================================== */

    if (length == 0 ||
        memcmp(data, original, length) == 0)
    {
        printf("\nRESULT: PASS\n");
        printf("Original data successfully recovered.\n");
    }
    else
    {
        printf("\nRESULT: FAIL\n");
        printf("Decrypted data does NOT match original.\n");
    }


    free(data);
}


/* ============================================
   MAIN
   ============================================ */

int main()
{
    const char *key = "TestKey123";


    /* ----------------------------------------
       TEST 1: EMPTY STRING
       ---------------------------------------- */

    const unsigned char empty[] = "";

    run_test(
        "Empty String",
        empty,
        0,
        key
    );


    /* ----------------------------------------
       TEST 2: SHORT TEXT
       ---------------------------------------- */

    const unsigned char short_text[] =
        "Hello World!";

    run_test(
        "Short Text",
        short_text,
        strlen((const char *)short_text),
        key
    );


    /* ----------------------------------------
       TEST 3: SPECIAL CHARACTERS
       ---------------------------------------- */

    const unsigned char special_text[] =
        "Hello! @#$%^&*()_+-={}[]|;:',.<>/?";

    run_test(
        "Special Characters",
        special_text,
        strlen((const char *)special_text),
        key
    );


    /* ----------------------------------------
       TEST 4: LONG TEXT
       ---------------------------------------- */

    unsigned char long_text[MAX_LONG_TEXT + 1];


    for (int i = 0; i < MAX_LONG_TEXT; i++)
    {
        long_text[i] =
            'A' + (i % 26);
    }

    long_text[MAX_LONG_TEXT] = '\0';


    run_test(
        "Long Text (10000 characters)",
        long_text,
        MAX_LONG_TEXT,
        key
    );


    /* ----------------------------------------
       TEST 5: DIFFERENT KEYS
       ---------------------------------------- */

    const unsigned char message[] =
        "Secure Chat Application";

    const char *key1 = "TestKey123";
    const char *key2 = "AnotherSecretKey";

    unsigned char cipher1[sizeof(message)];
    unsigned char cipher2[sizeof(message)];

    memcpy(cipher1, message, sizeof(message) - 1);
    memcpy(cipher2, message, sizeof(message) - 1);

    xor_crypt(cipher1, sizeof(message) - 1, key1);
    xor_crypt(cipher2, sizeof(message) - 1, key2);

    printf("\n========================================\n");
    printf("TEST: Same plaintext with different keys\n");
    printf("========================================\n");
    printf("Plaintext: %s\n", message);
    printf("Key 1: %s\n", key1);
    printf("Ciphertext 1 (HEX): ");
    print_hex(cipher1, sizeof(message) - 1);
    printf("Key 2: %s\n", key2);
    printf("Ciphertext 2 (HEX): ");
    print_hex(cipher2, sizeof(message) - 1);

    if (memcmp(cipher1, cipher2, sizeof(message) - 1) != 0)
    {
        printf("RESULT: PASS\n");
        printf("Different keys produced different ciphertexts.\n");
    }
    else
    {
        printf("RESULT: FAIL\n");
        printf("Different keys produced identical ciphertexts.\n");
    }

    printf("\n========================================\n");
    printf("ALL ENCRYPTION TESTS COMPLETED\n");
    printf("========================================\n");

    return 0;
}
