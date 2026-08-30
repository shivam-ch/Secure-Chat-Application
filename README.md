# Team SecureChat — Secure Chat Application

## Group Members

- Shivam Kumar Chaurasia (24052434) — server implementation, concurrency, protocol integration, and overall testing
- Aaditya Thakur (24052488) — client implementation, XOR cipher integration, and client-side testing
- Ritwika Dasgupta (24155995) — file-transfer implementation, error handling, and functional testing

## How to Build

This project uses POSIX TCP sockets and POSIX threads. It is intended to be built on Linux or WSL using GCC.
No external cryptography libraries are required.

```bash
gcc -Wall -Wextra -pthread server.c -o server
gcc -Wall -Wextra -pthread client.c -o client
gcc -Wall -Wextra test_cipher.c -o test_cipher
```

## How to Run

Start the server:

```bash
./server <port>
```

Example:

```bash
./server 8080
```

Start each client in a separate terminal:

```bash
./client <server_ip> <port>
```

Example:

```bash
./client 127.0.0.1 8080
```

The client asks for a unique username and a personal symmetric key.

## Commands

```text
LIST
SEND TO username: message
SENDFILE TO username: filename.txt
QUIT
```

`LIST` is an optional feature implemented by this project.

## Cipher Choice

We chose the **Repeating-Key XOR cipher**.

For every byte:

```text
ciphertext = plaintext XOR key
plaintext  = ciphertext XOR key
```

The key is repeated when the plaintext is longer than the key.

### Why XOR?

- Simple to implement ourselves.
- Encryption and decryption use the same operation.
- Works directly on arbitrary bytes, including file contents.
- Easy to combine with HEX encoding for safe transmission through the protocol.

### Known Weakness

Repeating-key XOR is **not a modern secure encryption algorithm**. Reusing a short key creates patterns and makes the cipher vulnerable to cryptanalysis. It provides confidentiality only for the purposes of this assignment and should not be used for real-world secure communication.

## Encryption Design

Every application message is encrypted before being sent over a socket.

The network representation is:

```text
Plaintext
   ↓
Repeating-Key XOR
   ↓
HEX encoding
   ↓
4-byte length-prefixed TCP frame
   ↓
Socket
```

The receiver reverses these steps:

```text
TCP frame
   ↓
HEX decoding
   ↓
XOR decryption
   ↓
Plaintext
```

### Registration Bootstrap Key

A new client does not yet have an established client-server key, so registration uses the shared bootstrap key:

```text
SecureChatBootstrap2026
```

The registration command is encrypted with this bootstrap key. The server decrypts it, extracts the username and the client's personal key, and stores them in its client table. The `REGISTERED` or registration `ERROR` response is also encrypted with the bootstrap key. After successful registration, all further communication for that client uses its personal key.

The bootstrap key is hard-coded for this project and is therefore a known limitation; it is not a secure real-world key-establishment mechanism.

## Client-to-Client Communication

The application uses **hop-by-hop encryption**, not end-to-end encryption.

For a message from `alpha` to `bravo`:

```text
alpha
  │ encrypt with alpha's key
  ▼
server
  │ decrypt with alpha's key
  │ temporarily holds plaintext
  │ encrypt with bravo's key
  ▼
bravo
  │ decrypt with bravo's key
  ▼
message
```

The server therefore briefly has access to the plaintext. True end-to-end encryption would require the clients to establish and use a shared key directly, so the server would never need to decrypt the message.

## File Transfer

Only `.txt` files are supported.

The client accepts either a relative filename or a full path:

```text
SENDFILE TO bravo: notes.txt
SENDFILE TO bravo: /path/to/notes.txt
```

The file is encrypted with the sender's key before it leaves the client. The server decrypts it with the sender's key and re-encrypts it with the receiver's key before forwarding it.

The receiver decrypts the file and saves it using a `received_` prefix, for example:

```text
received_notes.txt
```

### File Size Limit

The maximum supported original file size is **1 MB (1,048,576 bytes)**.

This avoids requiring chunked/streaming file transfer. Because encrypted file data is HEX encoded, the complete network frame is larger than the original file. The implementation therefore permits a larger encoded protocol frame (up to 5 MB) while still rejecting original files above the 1 MB assignment limit.

### File Framing

File contents can contain newlines, so the application does not use a newline as the TCP message boundary.

Instead, every network message uses:

```text
[4-byte network-order length][payload]
```

The receiver first reads the 4-byte length and then reads exactly that many bytes.

## Concurrency Model

The server uses **one POSIX thread per connected client**.

This was chosen because it is straightforward for a command-line chat application and allows several clients to receive and process commands concurrently.

A global mutex protects the shared client table. Each client also has a dedicated send mutex so complete frames sent to the same client cannot interleave. A small send-reference counter prevents the server from closing a client's socket while another server thread is forwarding a message to that client.

## Error Handling

The server handles:

- Duplicate usernames
- Offline recipients
- Invalid command formats
- Unknown commands
- Invalid encrypted/HEX data
- Oversized frames
- Invalid file headers/data
- Files larger than 1 MB
- Unsupported file extensions
- Abrupt client disconnections

The server continues running when an individual client sends malformed input or disconnects.

## Testing

Run the cipher tests:

```bash
./test_cipher
```

The test program checks:

- Empty input
- Short text
- Special characters
- Long text
- Encryption/decryption round trip
- Same plaintext encrypted with different keys produces different ciphertext

The full application will demonstrate:

1. At least three clients registered and chatting simultaneously.
2. Messages delivered only to the intended recipient.
3. Duplicate username rejected.
4. Sending to an offline user rejected.
5. Client terminated with `Ctrl+C`; server continues serving other clients.
6. Malformed/garbage encrypted input produces an error without crashing the server.
7. Two clients with different keys exchange the same plaintext and produce different ciphertext on the two client-server legs.
8. Small `.txt` file transferred successfully and recovered byte-for-byte.
9. Relative and full file paths both work.
10. Missing and oversized files are rejected cleanly.

### Wireshark Test

Captured the TCP connection between the client and server while sending the same plaintext from two clients with different personal keys.

The payload visible on the sender-to-server leg and the server-to-receiver leg was seen to be ciphertext/HEX data rather than the plaintext. Because different client keys are used, the ciphertext on the two legs differed even though the plaintext message is the same.

## Known Limitations

- Repeating-key XOR is intentionally simple and cryptographically weak.
- The bootstrap key is hard-coded.
- Encryption is hop-by-hop rather than end-to-end.
- Only text files are supported.
- Files are limited to 1 MB and are loaded into memory rather than streamed in chunks.
- The protocol is intended for this assignment and is not a production secure messaging protocol.
