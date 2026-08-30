#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>

#define MAX_USERNAME 50
#define MAX_KEY 128
#define MAX_MESSAGE 4096

#define MAX_FILE_SIZE (1024 * 1024)

/*
 * A 1 MB file becomes:
 *
 * Original file:        1 MB
 * Inner HEX encoding:   2 MB
 * Outer encrypted HEX:  4 MB approximately
 */
#define MAX_FRAME (5 * 1024 * 1024)


/*
 * IMPORTANT:
 * This key must be the same in server.c
 *
 * Used ONLY for encrypted registration.
 */
#define BOOTSTRAP_KEY "SecureChatBootstrap2026"


/* =====================================================
   XOR ENCRYPTION
   ===================================================== */

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


/* =====================================================
   HEX ENCODE
   ===================================================== */

void hex_encode(const unsigned char *input,
                size_t len,
                char *output)
{
    const char hex[] = "0123456789ABCDEF";

    for (size_t i = 0; i < len; i++)
    {
        output[i * 2] =
            hex[(input[i] >> 4) & 0x0F];

        output[i * 2 + 1] =
            hex[input[i] & 0x0F];
    }

    output[len * 2] = '\0';
}


/* =====================================================
   HEX DECODE
   ===================================================== */

int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    return -1;
}


int hex_decode(const char *input,
               unsigned char *output,
               size_t max_output)
{
    size_t len = strlen(input);

    if (len % 2 != 0)
        return -1;

    size_t output_len = len / 2;

    if (output_len > max_output)
        return -1;

    for (size_t i = 0; i < output_len; i++)
    {
        int high = hex_value(input[i * 2]);
        int low = hex_value(input[i * 2 + 1]);

        if (high < 0 || low < 0)
            return -1;

        output[i] =
            (unsigned char)((high << 4) | low);
    }

    return (int)output_len;
}


/* =====================================================
   SEND ALL
   ===================================================== */

int send_all(int socket_fd,
             const void *buffer,
             size_t length)
{
    size_t total_sent = 0;

    while (total_sent < length)
    {
        ssize_t sent =
            send(socket_fd,
                 (const char *)buffer + total_sent,
                 length - total_sent,
                 0);

        if (sent < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        if (sent == 0)
            return -1;

        total_sent += sent;
    }

    return 1;
}


/* =====================================================
   RECEIVE ALL
   ===================================================== */

int recv_all(int socket_fd,
             void *buffer,
             size_t length)
{
    size_t total_received = 0;

    while (total_received < length)
    {
        ssize_t received =
            recv(socket_fd,
                 (char *)buffer + total_received,
                 length - total_received,
                 0);

        if (received == 0)
            return 0;

        if (received < 0)
        {
            if (errno == EINTR)
                continue;

            return -1;
        }

        total_received += received;
    }

    return 1;
}


/* =====================================================
   SEND FRAME

   Format:

   [4-byte length][data]
   ===================================================== */

int send_frame(int socket_fd,
               const char *data,
               size_t length)
{
    if (length == 0 || length > MAX_FRAME)
        return -1;

    uint32_t network_length =
        htonl((uint32_t)length);

    if (send_all(socket_fd,
                 &network_length,
                 sizeof(network_length)) <= 0)
    {
        return -1;
    }

    if (send_all(socket_fd,
                 data,
                 length) <= 0)
    {
        return -1;
    }

    return 1;
}


/* =====================================================
   RECEIVE FRAME
   ===================================================== */

int recv_frame(int socket_fd,
               char **data)
{
    uint32_t network_length;

    int result =
        recv_all(socket_fd,
                 &network_length,
                 sizeof(network_length));

    if (result <= 0)
        return result;

    uint32_t length =
        ntohl(network_length);

    if (length == 0 || length > MAX_FRAME)
        return -1;

    *data = malloc(length + 1);

    if (*data == NULL)
        return -1;

    result =
        recv_all(socket_fd,
                 *data,
                 length);

    if (result <= 0)
    {
        free(*data);
        *data = NULL;

        return result;
    }

    (*data)[length] = '\0';

    return (int)length;
}


/* =====================================================
   SEND ENCRYPTED

   Plain text
       ↓
   XOR encryption
       ↓
   HEX encoding
       ↓
   Length-prefixed frame
   ===================================================== */

int send_encrypted(int socket_fd,
                   const char *message,
                   const char *key)
{
    size_t length = strlen(message);

    unsigned char *encrypted =
        malloc(length + 1);

    if (encrypted == NULL)
        return -1;

    memcpy(encrypted,
           message,
           length);

    xor_crypt(encrypted,
              length,
              key);

    char *hex =
        malloc(length * 2 + 1);

    if (hex == NULL)
    {
        free(encrypted);
        return -1;
    }

    hex_encode(encrypted,
               length,
               hex);

    int result =
        send_frame(socket_fd,
                   hex,
                   strlen(hex));

    free(encrypted);
    free(hex);

    return result;
}


/* =====================================================
   RECEIVE DECRYPTED

   Frame
       ↓
   HEX decode
       ↓
   XOR decrypt
   ===================================================== */

int receive_decrypted(int socket_fd,
                      const char *key,
                      unsigned char **output)
{
    char *frame = NULL;

    int frame_length =
        recv_frame(socket_fd,
                   &frame);

    if (frame_length <= 0)
        return frame_length;

    unsigned char *decoded =
        malloc(frame_length / 2 + 1);

    if (decoded == NULL)
    {
        free(frame);
        return -1;
    }

    int decoded_length =
        hex_decode(frame,
                   decoded,
                   frame_length / 2);

    free(frame);

    if (decoded_length < 0)
    {
        free(decoded);
        return -1;
    }

    xor_crypt(decoded,
              decoded_length,
              key);

    decoded[decoded_length] = '\0';

    *output = decoded;

    return decoded_length;
}


/* =====================================================
   RECEIVER THREAD DATA
   ===================================================== */

typedef struct
{
    int socket_fd;
    char key[MAX_KEY];

} ReceiverData;


/* =====================================================
   RECEIVE MESSAGES THREAD
   ===================================================== */

void *receive_messages(void *arg)
{
    ReceiverData *data =
        (ReceiverData *)arg;

    while (1)
    {
        unsigned char *message = NULL;

        int result =
            receive_decrypted(
                data->socket_fd,
                data->key,
                &message);

        if (result <= 0)
        {
            printf("\nDisconnected from server.\n");
            exit(0);
        }


        /* =============================================
           FILE RECEIVING
           ============================================= */

        if (strncmp((char *)message,
                    "RECVFILE FROM ",
                    14) == 0)
        {
            /*
             * Format:
             *
             * RECVFILE FROM sender filename size
             * HEX_DATA
             */

            char *newline =
                strchr((char *)message,
                       '\n');

            if (newline == NULL)
            {
                printf("\nERROR invalid file format\n");

                free(message);
                continue;
            }

            *newline = '\0';


            char sender[MAX_USERNAME];
            char filename[512];
            long file_size;


            if (sscanf((char *)message,
                       "RECVFILE FROM %49s %511s %ld",
                       sender,
                       filename,
                       &file_size) != 3)
            {
                printf("\nERROR invalid file header\n");

                free(message);
                continue;
            }


            if (file_size < 0 ||
                file_size > MAX_FILE_SIZE)
            {
                printf("\nERROR invalid file size\n");

                free(message);
                continue;
            }


            char *hex_data =
                newline + 1;


            size_t hex_length =
                strlen(hex_data);


            if (hex_length !=
                (size_t)file_size * 2)
            {
                printf("\nERROR invalid file data size\n");

                free(message);
                continue;
            }


            unsigned char *file_data =
                malloc(file_size + 1);


            if (file_data == NULL)
            {
                printf("\nERROR memory allocation failed\n");

                free(message);
                continue;
            }


            int decoded_length =
                hex_decode(hex_data,
                           file_data,
                           file_size);


            if (decoded_length != file_size)
            {
                printf("\nERROR invalid file data\n");

                free(file_data);
                free(message);

                continue;
            }


            /*
             * Decrypt file using receiver's key.
             */

            xor_crypt(file_data,
                      decoded_length,
                      data->key);


            /*
             * Save received file.
             */

            char output_filename[600];

            snprintf(output_filename,
                     sizeof(output_filename),
                     "received_%s",
                     filename);


            FILE *file =
                fopen(output_filename,
                      "wb");


            if (file == NULL)
            {
                printf("\nERROR cannot create file\n");

                free(file_data);
                free(message);

                continue;
            }


            fwrite(file_data,
                   1,
                   decoded_length,
                   file);

            fclose(file);


            printf("\n");
            printf("====================================\n");
            printf("FILE RECEIVED\n");
            printf("From: %s\n", sender);
            printf("File: %s\n", filename);
            printf("Size: %ld bytes\n", file_size);
            printf("Saved as: %s\n", output_filename);
            printf("====================================\n");


            free(file_data);
            free(message);

            printf("Enter command: ");
            fflush(stdout);

            continue;
        }


        /* =============================================
           NORMAL MESSAGE
           ============================================= */

        printf("\n%s\n", message);

        free(message);

        printf("Enter command: ");
        fflush(stdout);
    }

    return NULL;
}


/* =====================================================
   MAIN
   ===================================================== */

int main(int argc,
         char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <server_ip> <port>\n",
               argv[0]);

        return 1;
    }


    char *server_ip = argv[1];
    int port = atoi(argv[2]);


    /* Create socket */

    int socket_fd =
        socket(AF_INET,
               SOCK_STREAM,
               0);

    if (socket_fd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }


    struct sockaddr_in server;

    memset(&server,
           0,
           sizeof(server));

    server.sin_family = AF_INET;
    server.sin_port = htons(port);


    if (inet_pton(AF_INET,
                  server_ip,
                  &server.sin_addr) <= 0)
    {
        printf("Invalid server IP\n");

        close(socket_fd);

        return 1;
    }


    if (connect(socket_fd,
                (struct sockaddr *)&server,
                sizeof(server)) < 0)
    {
        perror("Connection failed");

        close(socket_fd);

        return 1;
    }


    printf("Connected to server!\n");


    /* =============================================
       GET USER DETAILS
       ============================================= */

    char username[MAX_USERNAME];
    char personal_key[MAX_KEY];


    printf("Enter username: ");
    scanf("%49s", username);


    printf("Enter personal key: ");
    scanf("%127s", personal_key);


    getchar();


    /* =============================================
       ENCRYPTED REGISTRATION

       Registration uses BOOTSTRAP_KEY
       ============================================= */

    char registration[300];


    snprintf(registration,
             sizeof(registration),
             "REGISTER %s KEY %s",
             username,
             personal_key);


    printf("Sending encrypted registration...\n");


    if (send_encrypted(socket_fd,
                       registration,
                       BOOTSTRAP_KEY) < 0)
    {
        printf("Registration send failed.\n");

        close(socket_fd);

        return 1;
    }


    /* Receive encrypted registration response */

    unsigned char *response = NULL;


    int response_length =
        receive_decrypted(socket_fd,
                          BOOTSTRAP_KEY,
                          &response);


    if (response_length <= 0)
    {
        printf("Registration failed.\n");

        close(socket_fd);

        return 1;
    }


    if (strncmp((char *)response,
                "ERROR",
                5) == 0)
    {
        printf("%s\n", response);

        free(response);

        close(socket_fd);

        return 1;
    }


    if (strcmp((char *)response,
               "REGISTERED") != 0)
    {
        printf("Unexpected server response: %s\n",
               response);

        free(response);

        close(socket_fd);

        return 1;
    }


    free(response);


    printf("Registration successful!\n");
    printf("All future communication uses your personal key.\n\n");


    /* =============================================
       START RECEIVER THREAD
       ============================================= */

    ReceiverData receiver_data;

    receiver_data.socket_fd =
        socket_fd;


    strncpy(receiver_data.key,
            personal_key,
            MAX_KEY - 1);

    receiver_data.key[MAX_KEY - 1] =
        '\0';


    pthread_t receiver_thread;


    if (pthread_create(&receiver_thread,
                       NULL,
                       receive_messages,
                       &receiver_data) != 0)
    {
        perror("Thread creation failed");

        close(socket_fd);

        return 1;
    }


    /* =============================================
       COMMAND LOOP
       ============================================= */

    char command[MAX_MESSAGE];


    printf("Commands:\n");
    printf("  LIST\n");
    printf("  SEND TO username: message\n");
    printf("  SENDFILE TO username: filename.txt\n");
    printf("  QUIT\n\n");


    while (1)
    {
        printf("Enter command: ");
        fflush(stdout);


        if (fgets(command,
                  sizeof(command),
                  stdin) == NULL)
        {
            break;
        }


        command[strcspn(command,
                        "\n")] = '\0';


        if (strlen(command) == 0)
            continue;


        /* =========================================
           QUIT
           ========================================= */

        if (strcmp(command,
                   "QUIT") == 0)
        {
            send_encrypted(socket_fd,
                           command,
                           personal_key);

            sleep(1);

            break;
        }


        /* =========================================
           SENDFILE
           ========================================= */

        if (strncmp(command,
                    "SENDFILE TO ",
                    12) == 0)
        {
            char target[MAX_USERNAME];
            char filename[512];


            char *colon =
                strchr(command,
                       ':');


            if (colon == NULL)
            {
                printf("ERROR format:\n");
                printf("SENDFILE TO username: filename.txt\n");

                continue;
            }


            *colon = '\0';


            if (sscanf(command + 12,
                       "%49s",
                       target) != 1)
            {
                printf("ERROR invalid target\n");

                continue;
            }


            strncpy(filename,
                    colon + 1,
                    sizeof(filename) - 1);

            filename[sizeof(filename) - 1] =
                '\0';


            /* Remove leading spaces */

            while (filename[0] == ' ')
            {
                memmove(filename,
                        filename + 1,
                        strlen(filename));
            }


            /* Check extension */

            char *dot =
                strrchr(filename,
                       '.');


            if (dot == NULL ||
                strcmp(dot,
                       ".txt") != 0)
            {
                printf("ERROR only .txt files are supported\n");

                continue;
            }


            /* Open file */

            FILE *file =
                fopen(filename,
                      "rb");


            if (file == NULL)
            {
                printf("ERROR file not found: %s\n",
                       filename);

                continue;
            }


            fseek(file,
                  0,
                  SEEK_END);

            long file_size =
                ftell(file);


            fseek(file,
                  0,
                  SEEK_SET);


            if (file_size < 0 ||
                file_size > MAX_FILE_SIZE)
            {
                fclose(file);

                printf("ERROR file exceeds 1MB limit\n");

                continue;
            }


            /* Read file */

            unsigned char *file_data =
                malloc(file_size + 1);


            if (file_data == NULL)
            {
                fclose(file);

                printf("ERROR memory allocation failed\n");

                continue;
            }


            size_t bytes_read =
                fread(file_data,
                      1,
                      file_size,
                      file);


            fclose(file);


            if (bytes_read !=
                (size_t)file_size)
            {
                printf("ERROR reading file\n");

                free(file_data);

                continue;
            }


            /*
             * STEP 1:
             * Encrypt file using SENDER'S PERSONAL KEY
             */

            xor_crypt(file_data,
                      file_size,
                      personal_key);


            /*
             * STEP 2:
             * Convert encrypted binary data to HEX
             */

            char *hex_data =
                malloc(file_size * 2 + 1);


            if (hex_data == NULL)
            {
                free(file_data);

                printf("ERROR memory allocation failed\n");

                continue;
            }


            hex_encode(file_data,
                       file_size,
                       hex_data);


            /*
             * Extract simple filename.
             */

            const char *basename =
                strrchr(filename,
                       '/');


            if (basename != NULL)
                basename++;
            else
                basename = filename;


            /*
             * STEP 3:
             * Create file message.
             *
             * Format:
             *
             * SENDFILE TO username filename size
             * HEX_ENCRYPTED_FILE
             */

            size_t message_size =
                strlen("SENDFILE TO ") +
                strlen(target) +
                strlen(basename) +
                strlen(hex_data) +
                100;


            char *file_message =
                malloc(message_size);


            if (file_message == NULL)
            {
                free(file_data);
                free(hex_data);

                printf("ERROR memory allocation failed\n");

                continue;
            }


            snprintf(file_message,
                     message_size,
                     "SENDFILE TO %s %s %ld\n%s",
                     target,
                     basename,
                     file_size,
                     hex_data);


            /*
             * STEP 4:
             * Encrypt complete message again
             * for client-server communication.
             */

            if (send_encrypted(socket_fd,
                               file_message,
                               personal_key) < 0)
            {
                printf("ERROR sending file\n");
            }
            else
            {
                printf("File sent to server.\n");
            }


            free(file_data);
            free(hex_data);
            free(file_message);

            continue;
        }


        /* =========================================
           NORMAL COMMAND
           ========================================= */

        if (send_encrypted(socket_fd,
                           command,
                           personal_key) < 0)
        {
            printf("ERROR sending command\n");

            break;
        }
    }


    close(socket_fd);

    return 0;
}
