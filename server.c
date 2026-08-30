#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>

#define MAX_CLIENTS 50
#define MAX_USERNAME 50
#define MAX_KEY 128
#define MAX_MESSAGE 4096

#define MAX_FILE_SIZE (1024 * 1024)
#define MAX_FRAME (5 * 1024 * 1024)


/*
 * IMPORTANT:
 * Must be exactly the same as client.c
 *
 * Used only for encrypted registration.
 */
#define BOOTSTRAP_KEY "SecureChatBootstrap2026"


/* =====================================================
   CLIENT STRUCTURE
   ===================================================== */

typedef struct
{
    int socket;
    char username[MAX_USERNAME];
    char key[MAX_KEY];
    int active;

    /* Protects complete frames sent to this client. */
    pthread_mutex_t send_mutex;

    /* Prevents the socket from being closed while another
       server thread is sending to this client. */
    int send_refs;

} Client;


Client clients[MAX_CLIENTS];


pthread_mutex_t clients_mutex =
    PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t clients_condition =
    PTHREAD_COND_INITIALIZER;


/* =====================================================
   XOR ENCRYPTION
   ===================================================== */

void xor_crypt(unsigned char *data,
               size_t len,
               const char *key)
{
    size_t key_len = strlen(key);

    if (key_len == 0)
        return;

    for (size_t i = 0; i < len; i++)
    {
        data[i] ^=
            key[i % key_len];
    }
}


/* =====================================================
   HEX ENCODE
   ===================================================== */

void hex_encode(const unsigned char *input,
                size_t len,
                char *output)
{
    const char hex[] =
        "0123456789ABCDEF";

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

    size_t output_len =
        len / 2;

    if (output_len > max_output)
        return -1;

    for (size_t i = 0; i < output_len; i++)
    {
        int high =
            hex_value(input[i * 2]);

        int low =
            hex_value(input[i * 2 + 1]);

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
   ===================================================== */

int send_frame(int socket_fd,
               const char *data,
               size_t length)
{
    if (length == 0)
        return -1;

    if (length > MAX_FRAME)
        return -2;


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


    if (length == 0)
        return -1;

    if (length > MAX_FRAME)
        return -2;


    *data =
        malloc(length + 1);


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
   ===================================================== */

int send_encrypted(int socket_fd,
                   const char *message,
                   const char *key)
{
    size_t length =
        strlen(message);


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
   FIND CLIENT BY USERNAME

   Must be called while mutex is locked.
   ===================================================== */

int find_client_by_username(
    const char *username)
{
    for (int i = 0;
         i < MAX_CLIENTS;
         i++)
    {
        if (clients[i].active &&
            strcmp(clients[i].username,
                   username) == 0)
        {
            return i;
        }
    }

    return -1;
}


/* =====================================================
   SEND TO ANOTHER CLIENT SAFELY

   A target can disconnect while another client is sending
   to it. The reference count keeps the socket alive until
   the send finishes, while send_mutex prevents two complete
   frames from being interleaved on the same socket.
   ===================================================== */

int send_to_client(int target_index,
                   const char *expected_username,
                   const char *message)
{
    int target_socket;
    char target_key[MAX_KEY];

    pthread_mutex_lock(&clients_mutex);

    if (!clients[target_index].active ||
        strcmp(clients[target_index].username,
               expected_username) != 0)
    {
        pthread_mutex_unlock(&clients_mutex);
        return -1;
    }

    target_socket = clients[target_index].socket;

    strncpy(target_key,
            clients[target_index].key,
            MAX_KEY - 1);
    target_key[MAX_KEY - 1] = '\0';

    clients[target_index].send_refs++;

    pthread_mutex_unlock(&clients_mutex);

    pthread_mutex_lock(&clients[target_index].send_mutex);

    int result =
        send_encrypted(target_socket,
                       message,
                       target_key);

    pthread_mutex_unlock(&clients[target_index].send_mutex);

    pthread_mutex_lock(&clients_mutex);

    clients[target_index].send_refs--;

    if (clients[target_index].send_refs == 0)
        pthread_cond_broadcast(&clients_condition);

    pthread_mutex_unlock(&clients_mutex);

    return result;
}


/* =====================================================
   REMOVE CLIENT
   ===================================================== */

void remove_client(int index)
{
    pthread_mutex_lock(&clients_mutex);

    if (clients[index].active)
    {
        printf("Client disconnected: %s\n",
               clients[index].username);

        clients[index].active = 0;

        /* Wait for any in-progress send to finish. */
        while (clients[index].send_refs > 0)
            pthread_cond_wait(&clients_condition,
                              &clients_mutex);

        clients[index].socket = -1;
        clients[index].username[0] = '\0';
        clients[index].key[0] = '\0';
    }

    pthread_mutex_unlock(&clients_mutex);
}

/* =====================================================
   HANDLE CLIENT
   ===================================================== */

void *handle_client(void *arg)
{
    int client_index =
        *(int *)arg;

    free(arg);


    int socket_fd =
        clients[client_index].socket;


    /* =============================================
       ENCRYPTED REGISTRATION

       Uses BOOTSTRAP_KEY
       ============================================= */

    unsigned char *registration =
        NULL;


    int registration_length =
        receive_decrypted(
            socket_fd,
            BOOTSTRAP_KEY,
            &registration);


    if (registration_length <= 0)
    {
        remove_client(client_index);

        close(socket_fd);

        return NULL;
    }


    char username[MAX_USERNAME];
    char personal_key[MAX_KEY];


    if (sscanf((char *)registration,
               "REGISTER %49s KEY %127s",
               username,
               personal_key) != 2)
    {
        send_encrypted(
            socket_fd,
            "ERROR invalid registration format",
            BOOTSTRAP_KEY);

        free(registration);

        remove_client(client_index);

        close(socket_fd);

        return NULL;
    }


    /*
     * Registration message is no longer needed.
     */

    free(registration);


    /* =============================================
       CHECK USERNAME
       ============================================= */

    pthread_mutex_lock(
        &clients_mutex);


    int duplicate =
        find_client_by_username(username);


    if (duplicate != -1)
    {
        pthread_mutex_unlock(
            &clients_mutex);


        char error[256];
        snprintf(error,
                 sizeof(error),
                 "ERROR username %s already taken",
                 username);

        send_encrypted(
            socket_fd,
            error,
            BOOTSTRAP_KEY);


        remove_client(client_index);

        close(socket_fd);

        return NULL;
    }


    /*
     * Store username and personal key.
     */

    strncpy(clients[client_index].username,
            username,
            MAX_USERNAME - 1);

    clients[client_index]
        .username[MAX_USERNAME - 1] =
        '\0';


    strncpy(clients[client_index].key,
            personal_key,
            MAX_KEY - 1);

    clients[client_index]
        .key[MAX_KEY - 1] =
        '\0';


    pthread_mutex_unlock(
        &clients_mutex);


    printf("Registered client: %s\n",
           username);


    /*
     * Registration confirmation also uses
     * BOOTSTRAP_KEY because client has not
     * switched to personal key yet.
     */

    send_encrypted(
        socket_fd,
        "REGISTERED",
        BOOTSTRAP_KEY);


    /*
     * From this point onward:
     *
     * Client <-> Server
     *
     * uses client's PERSONAL KEY
     */


    while (1)
    {
        unsigned char *message =
            NULL;


        int result =
            receive_decrypted(
                socket_fd,
                clients[client_index].key,
                &message);


        if (result == 0)
        {
            break;
        }

        if (result == -2)
        {
            send_encrypted(
                socket_fd,
                "ERROR message frame too large",
                clients[client_index].key);
            break;
        }

        if (result < 0)
        {
            send_encrypted(
                socket_fd,
                "ERROR malformed encrypted message",
                clients[client_index].key);
            continue;
        }


        printf("[%s] Command received\n",
               username);


        /* =========================================
           QUIT
           ========================================= */

        if (strcmp((char *)message,
                   "QUIT") == 0)
        {
            send_encrypted(
                socket_fd,
                "GOODBYE",
                clients[client_index].key);

            free(message);

            break;
        }


        /* =========================================
           LIST
           ========================================= */

        if (strcmp((char *)message,
                   "LIST") == 0)
        {
            char online[MAX_MESSAGE];

            strcpy(online,
                   "ONLINE: ");


            pthread_mutex_lock(
                &clients_mutex);


            int first = 1;


            for (int i = 0;
                 i < MAX_CLIENTS;
                 i++)
            {
                if (clients[i].active &&
                    clients[i].username[0] != '\0')
                {
                    if (!first)
                    {
                        strcat(online,
                               ", ");
                    }

                    strcat(online,
                           clients[i].username);

                    first = 0;
                }
            }


            pthread_mutex_unlock(
                &clients_mutex);


            send_encrypted(
                socket_fd,
                online,
                clients[client_index].key);


            free(message);

            continue;
        }


        /* =========================================
           SEND TO USER
           ========================================= */

        if (strncmp((char *)message,
                    "SEND ",
                    5) == 0 &&
            strncmp((char *)message,
                    "SEND TO ",
                    8) != 0)
        {
            send_encrypted(
                socket_fd,
                "ERROR invalid command format",
                clients[client_index].key);

            free(message);
            continue;
        }

        if (strncmp((char *)message,
                    "SEND TO ",
                    8) == 0)
        {
            char target[MAX_USERNAME];

            char *colon =
                strchr((char *)message,
                       ':');


            if (colon == NULL)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR invalid message format",
                    clients[client_index].key);

                free(message);

                continue;
            }


            *colon = '\0';


            if (sscanf((char *)message + 8,
                       "%49s",
                       target) != 1)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR invalid target",
                    clients[client_index].key);

                free(message);

                continue;
            }


            char *text =
                colon + 1;


            while (*text == ' ')
                text++;


            pthread_mutex_lock(
                &clients_mutex);


            int target_index =
                find_client_by_username(target);


            if (target_index == -1)
            {
                pthread_mutex_unlock(
                    &clients_mutex);


                char error[256];

                snprintf(error,
                         sizeof(error),
                         "ERROR %s is not online",
                         target);


                send_encrypted(
                    socket_fd,
                    error,
                    clients[client_index].key);


                free(message);

                continue;
            }


            pthread_mutex_unlock(
                &clients_mutex);


            size_t outgoing_length =
                strlen("FROM ") +
                strlen(username) +
                strlen(": ") +
                strlen(text) + 1;

            char *outgoing =
                malloc(outgoing_length);

            if (outgoing == NULL)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR memory allocation failed",
                    clients[client_index].key);

                free(message);
                continue;
            }

            snprintf(outgoing,
                     outgoing_length,
                     "FROM %s: %s",
                     username,
                     text);

            /*
             * Server encrypts outgoing message
             * using receiver's personal key.
             */

            send_to_client(target_index,
                           target,
                           outgoing);

            free(outgoing);


            free(message);

            continue;
        }


        /* =========================================
           SENDFILE
           ========================================= */

        if (strncmp((char *)message,
                    "SENDFILE TO ",
                    12) == 0)
        {
            /*
             * Expected format:
             *
             * SENDFILE TO receiver filename size
             * HEX_ENCRYPTED_FILE_DATA
             */


            char target[MAX_USERNAME];
            char filename[512];
            long file_size;


            char *newline =
                strchr((char *)message,
                       '\n');


            if (newline == NULL)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR invalid file format",
                    clients[client_index].key);

                free(message);

                continue;
            }


            *newline = '\0';


            if (sscanf((char *)message,
                       "SENDFILE TO %49s %511s %ld",
                       target,
                       filename,
                       &file_size) != 3)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR invalid file header",
                    clients[client_index].key);

                free(message);

                continue;
            }


            if (file_size < 0 ||
                file_size > MAX_FILE_SIZE)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR file exceeds 1MB limit",
                    clients[client_index].key);

                free(message);

                continue;
            }


            /*
             * Only .txt files allowed.
             */

            char *dot =
                strrchr(filename,
                       '.');


            if (dot == NULL ||
                strcmp(dot,
                       ".txt") != 0)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR only .txt files allowed",
                    clients[client_index].key);

                free(message);

                continue;
            }


            /* Find receiver */

            pthread_mutex_lock(
                &clients_mutex);


            int target_index =
                find_client_by_username(target);


            if (target_index == -1)
            {
                pthread_mutex_unlock(
                    &clients_mutex);


                char error[256];

                snprintf(error,
                         sizeof(error),
                         "ERROR %s is not online",
                         target);


                send_encrypted(
                    socket_fd,
                    error,
                    clients[client_index].key);


                free(message);

                continue;
            }


            char target_key[MAX_KEY];

            strncpy(target_key,
                    clients[target_index].key,
                    MAX_KEY - 1);
            target_key[MAX_KEY - 1] = '\0';


            pthread_mutex_unlock(
                &clients_mutex);


            /*
             * Get encrypted file HEX data.
             */

            char *hex_data =
                newline + 1;


            size_t hex_length =
                strlen(hex_data);


            if (hex_length !=
                (size_t)file_size * 2)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR invalid file data size",
                    clients[client_index].key);

                free(message);

                continue;
            }


            /*
             * Convert HEX back to encrypted bytes.
             */

            unsigned char *file_data =
                malloc(file_size + 1);


            if (file_data == NULL)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR memory allocation failed",
                    clients[client_index].key);

                free(message);

                continue;
            }


            int decoded_length =
                hex_decode(
                    hex_data,
                    file_data,
                    file_size);


            if (decoded_length != file_size)
            {
                free(file_data);

                send_encrypted(
                    socket_fd,
                    "ERROR invalid file data",
                    clients[client_index].key);

                free(message);

                continue;
            }


            /*
             * =========================================
             * REQUIRED FILE SECURITY FLOW
             * =========================================
             *
             * 1. Client encrypted file using sender key.
             *
             * 2. Server decrypts using sender key.
             */

            xor_crypt(
                file_data,
                file_size,
                clients[client_index].key);


            /*
             * 3. Server re-encrypts using receiver key.
             */

            xor_crypt(
                file_data,
                file_size,
                target_key);


            /*
             * Convert receiver-encrypted file
             * to HEX for safe transmission.
             */

            char *receiver_hex =
                malloc(file_size * 2 + 1);


            if (receiver_hex == NULL)
            {
                free(file_data);

                send_encrypted(
                    socket_fd,
                    "ERROR memory allocation failed",
                    clients[client_index].key);

                free(message);

                continue;
            }


            hex_encode(
                file_data,
                file_size,
                receiver_hex);


            /*
             * Create outgoing message.
             *
             * Format:
             *
             * RECVFILE FROM sender filename size
             * HEX_DATA
             */

            size_t outgoing_size =
                strlen("RECVFILE FROM ") +
                strlen(username) +
                strlen(filename) +
                strlen(receiver_hex) +
                100;


            char *outgoing_message =
                malloc(outgoing_size);


            if (outgoing_message == NULL)
            {
                free(file_data);
                free(receiver_hex);

                send_encrypted(
                    socket_fd,
                    "ERROR memory allocation failed",
                    clients[client_index].key);

                free(message);

                continue;
            }


            snprintf(
                outgoing_message,
                outgoing_size,
                "RECVFILE FROM %s %s %ld\n%s",
                username,
                filename,
                file_size,
                receiver_hex);


            /*
             * Encrypt entire network message
             * using receiver's personal key.
             */

            int send_result =
                send_to_client(target_index,
                               target,
                               outgoing_message);


            free(file_data);
            free(receiver_hex);
            free(outgoing_message);


            if (send_result < 0)
            {
                send_encrypted(
                    socket_fd,
                    "ERROR failed to send file",
                    clients[client_index].key);
            }
            else
            {
                char confirmation[256];

                snprintf(
                    confirmation,
                    sizeof(confirmation),
                    "FILE SENT TO %s",
                    target);


                send_encrypted(
                    socket_fd,
                    confirmation,
                    clients[client_index].key);
            }


            free(message);

            continue;
        }


        /* =========================================
           UNKNOWN COMMAND
           ========================================= */

        send_encrypted(
            socket_fd,
            "ERROR unknown command",
            clients[client_index].key);


        free(message);
    }


    remove_client(client_index);

    close(socket_fd);

    return NULL;
}


/* =====================================================
   MAIN SERVER
   ===================================================== */

int main(int argc,
         char *argv[])
{
    /*
     * Prevent server from crashing if a client
     * disconnects while server sends data.
     */

    signal(SIGPIPE,
           SIG_IGN);


    int port = 8080;


    if (argc >= 2)
    {
        port = atoi(argv[1]);
    }


    /* Create socket */

    int server_fd =
        socket(AF_INET,
               SOCK_STREAM,
               0);


    if (server_fd < 0)
    {
        perror("Socket creation failed");

        return 1;
    }


    int option = 1;


    setsockopt(server_fd,
               SOL_SOCKET,
               SO_REUSEADDR,
               &option,
               sizeof(option));


    struct sockaddr_in server_address;


    memset(&server_address,
           0,
           sizeof(server_address));


    server_address.sin_family =
        AF_INET;

    server_address.sin_addr.s_addr =
        INADDR_ANY;

    server_address.sin_port =
        htons(port);


    /* Bind */

    if (bind(server_fd,
             (struct sockaddr *)&server_address,
             sizeof(server_address)) < 0)
    {
        perror("Bind failed");

        close(server_fd);

        return 1;
    }


    /* Listen */

    if (listen(server_fd,
               10) < 0)
    {
        perror("Listen failed");

        close(server_fd);

        return 1;
    }


    /* Initialize client array */

    for (int i = 0;
         i < MAX_CLIENTS;
         i++)
    {
        clients[i].socket = -1;
        clients[i].active = 0;
        clients[i].username[0] = '\0';
        clients[i].key[0] = '\0';
        clients[i].send_refs = 0;
        pthread_mutex_init(&clients[i].send_mutex, NULL);
    }


    printf("====================================\n");
    printf("Secure Chat Server\n");
    printf("Port: %d\n", port);
    printf("Encrypted registration enabled\n");
    printf("====================================\n");


    /* =============================================
       ACCEPT CLIENTS
       ============================================= */

    while (1)
    {
        struct sockaddr_in client_address;

        socklen_t client_length =
            sizeof(client_address);


        int client_socket =
            accept(
                server_fd,
                (struct sockaddr *)&client_address,
                &client_length);


        if (client_socket < 0)
        {
            perror("Accept failed");

            continue;
        }


        pthread_mutex_lock(
            &clients_mutex);


        int free_index =
            -1;


        for (int i = 0;
             i < MAX_CLIENTS;
             i++)
        {
            if (!clients[i].active)
            {
                free_index = i;
                break;
            }
        }


        if (free_index == -1)
        {
            pthread_mutex_unlock(
                &clients_mutex);


            close(client_socket);

            continue;
        }


        clients[free_index].socket =
            client_socket;

        clients[free_index].active =
            1;

        clients[free_index].username[0] =
            '\0';

        clients[free_index].key[0] =
            '\0';


        pthread_mutex_unlock(
            &clients_mutex);


        int *client_index =
            malloc(sizeof(int));


        if (client_index == NULL)
        {
            remove_client(free_index);

            close(client_socket);

            continue;
        }


        *client_index =
            free_index;


        pthread_t thread;


        if (pthread_create(
                &thread,
                NULL,
                handle_client,
                client_index) != 0)
        {
            perror("Thread creation failed");

            free(client_index);

            remove_client(free_index);

            close(client_socket);

            continue;
        }


        pthread_detach(thread);
    }


    close(server_fd);

    return 0;
}
