# Architecture Documentation

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Component Details](#component-details)
- [Data Flow](#data-flow)
- [Security Architecture](#security-architecture)
- [Module Lifecycle](#module-lifecycle)
- [Signal System](#signal-system)
- [State Management](#state-management)
- [Performance Considerations](#performance-considerations)
- [Extension Points](#extension-points)

---

## Overview

The irssi-fe-web module is a multi-layered system that bridges irssi's IRC functionality with modern web browsers through a secure WebSocket interface. The architecture follows a clean separation of concerns, with distinct layers for networking, encryption, protocol handling, and IRC event processing.

### Design Principles

1. **Security First**: Multiple layers of encryption and authentication
2. **Modularity**: Clear separation between components
3. **Extensibility**: Easy to add new message types and features
4. **Performance**: Efficient message routing and minimal overhead
5. **Standards Compliance**: RFC 6455 (WebSocket), OpenSSL, AES-256-GCM

---

## System Architecture

### High-Level Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      Web Browser Clients                       │
│                  (Multiple concurrent connections)             │
└───────────────────────────┬────────────────────────────────────┘
                            │
                            │ wss:// (WebSocket Secure)
                            │ Multiple clients over TCP
                            │
┌───────────────────────────▼────────────────────────────────────┐
│                     NETWORK LAYER                              │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  fe-web-ssl.c - SSL/TLS Encryption                       │ │
│  │  • OpenSSL wrapper                                       │ │
│  │  • Self-signed certificate generation                    │ │
│  │  • Non-blocking SSL accept/read/write                    │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────┬────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────┐
│                    PROTOCOL LAYER                              │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  fe-web-server.c - WebSocket Server                      │ │
│  │  • TCP accept() and connection management                │ │
│  │  • HTTP/WebSocket handshake                              │ │
│  │  • Password verification                                 │ │
│  │  • Client list management                                │ │
│  └────────────────┬─────────────────────────────────────────┘ │
│                   │                                            │
│  ┌────────────────▼─────────────────────────────────────────┐ │
│  │  fe-web-websocket.c - WebSocket Protocol (RFC 6455)      │ │
│  │  • Frame parsing and construction                        │ │
│  │  • Masking/unmasking                                     │ │
│  │  • Opcode handling (text, binary, ping, pong, close)    │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────┬────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────┐
│                   ENCRYPTION LAYER                             │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  fe-web-crypto.c - AES-256-GCM Encryption                │ │
│  │  • PBKDF2 key derivation from password                   │ │
│  │  • Per-message IV generation                             │ │
│  │  • Authenticated encryption/decryption                   │ │
│  │  • Authentication tag verification                       │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────┬────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────┐
│                   APPLICATION LAYER                            │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  fe-web-json.c - JSON Processing                         │ │
│  │  • JSON parsing (simple pattern-based)                   │ │
│  │  • JSON serialization                                    │ │
│  │  • String escaping/unescaping                            │ │
│  └────────────────┬─────────────────────────────────────────┘ │
│                   │                                            │
│  ┌────────────────▼─────────────────────────────────────────┐ │
│  │  fe-web-client.c - Client Request Dispatcher             │ │
│  │  • Message type routing                                  │ │
│  │  • Command execution                                     │ │
│  │  • Client state management                               │ │
│  └──────────┬───────────────────────────┬───────────────────┘ │
│             │                           │                     │
│  ┌──────────▼──────────────┐  ┌────────▼────────────────────┐ │
│  │  fe-web-signals.c       │  │  fe-web-netserver.c         │ │
│  │  IRC Event Handlers     │  │  Network/Server Config      │ │
│  │  • 55+ signal handlers  │  │  • Add/remove networks      │ │
│  │  • Event→Message conv.  │  │  • Add/remove servers       │ │
│  │  • Message broadcasting │  │  • Config persistence       │ │
│  └──────────┬──────────────┘  └─────────────────────────────┘ │
│             │                                                  │
│  ┌──────────▼──────────────────────────────────────────────┐  │
│  │  fe-web-utils.c - Utilities                             │  │
│  │  • Message allocation/deallocation                      │  │
│  │  • JSON serialization helpers                           │  │
│  │  • Message ID generation                                │  │
│  │  • Message sending (single/broadcast)                   │  │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────┬────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────┐
│                      INTEGRATION LAYER                         │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │  fe-web.c - Module Initialization                        │ │
│  │  • Settings registration                                 │ │
│  │  • Command registration (/FE_WEB)                        │ │
│  │  • Module lifecycle management                           │ │
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────┬────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────┐
│                        irssi Core                              │
│  • IRC protocol implementation                                 │
│  • Server/channel/query management                             │
│  • Signal emission system                                      │
│  • Settings system                                             │
│  • Window management                                           │
└────────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. fe-web.c - Module Core

**Responsibilities:**
- Module initialization and cleanup
- Settings registration with irssi
- Command registration (`/FE_WEB`)
- Server lifecycle management

**Key Functions:**

```c
void fe_web_init(void)
{
    // Register settings
    settings_add_bool("lookandfeel", "fe_web_enabled", FALSE);
    settings_add_int("lookandfeel", "fe_web_port", 9001);
    settings_add_str("lookandfeel", "fe_web_bind", "127.0.0.1");
    settings_add_str("lookandfeel", "fe_web_password", "");

    // Register commands
    command_bind("fe_web", NULL, (SIGNAL_FUNC) cmd_fe_web);

    // Initialize subsystems
    fe_web_signals_init();
    fe_web_ssl_init();
    fe_web_crypto_init();

    // Start server if enabled
    if (settings_get_bool("fe_web_enabled"))
        fe_web_server_init();

    // Watch for setting changes
    signal_add("setup changed", (SIGNAL_FUNC) fe_web_setup_changed);
}
```

**Settings:**

| Setting | Type | Default | Purpose |
|---------|------|---------|---------|
| `fe_web_enabled` | bool | FALSE | Enable/disable module |
| `fe_web_port` | int | 9001 | Listening port |
| `fe_web_bind` | string | 127.0.0.1 | Bind address |
| `fe_web_password` | string | "" | Auth password (required) |

---

### 2. fe-web-server.c - WebSocket Server

**Responsibilities:**
- TCP socket creation and binding
- Connection acceptance
- HTTP/WebSocket handshake
- Password verification
- Input/output event handling
- Client lifecycle management

**Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│                   Server Lifecycle                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. fe_web_server_init()                               │
│     ├─ Validate password configured                    │
│     ├─ Create listening socket                         │
│     ├─ Bind to fe_web_bind:fe_web_port                │
│     ├─ Listen for connections                          │
│     └─ Register accept handler (sig_listen)            │
│                                                         │
│  2. sig_listen() - New connection                      │
│     ├─ Accept socket                                   │
│     ├─ Create WEB_CLIENT_REC                           │
│     ├─ Wrap in SSL channel                             │
│     ├─ Register input handler (client_input)           │
│     └─ Add to web_clients list                         │
│                                                         │
│  3. client_input() - Data received                     │
│     ├─ Perform SSL handshake (if needed)               │
│     ├─ Read data into input_buffer                     │
│     ├─ If handshake not done:                          │
│     │  └─ fe_web_handle_handshake()                    │
│     └─ Else:                                           │
│        └─ fe_web_handle_websocket_data()               │
│                                                         │
│  4. fe_web_handle_handshake()                          │
│     ├─ Parse HTTP request                              │
│     ├─ Extract Sec-WebSocket-Key                       │
│     ├─ Verify password from query parameter            │
│     ├─ Compute accept key                              │
│     ├─ Send HTTP 101 response                          │
│     ├─ Set handshake_done = 1                          │
│     ├─ Set authenticated = 1                           │
│     └─ Send auth_ok message                            │
│                                                         │
│  5. fe_web_handle_websocket_data()                     │
│     ├─ Parse WebSocket frames                          │
│     ├─ Handle opcodes:                                 │
│     │  ├─ 0x1 (Text): Parse JSON                       │
│     │  ├─ 0x2 (Binary): Decrypt then parse JSON        │
│     │  ├─ 0x8 (Close): Close connection                │
│     │  └─ 0x9 (Ping): Send pong                        │
│     └─ Call fe_web_client_handle_message()             │
│                                                         │
│  6. fe_web_close_client()                              │
│     ├─ Remove input handler                            │
│     ├─ Close SSL channel                               │
│     ├─ Destroy send buffer                             │
│     └─ Call fe_web_client_destroy()                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**Connection Flow:**

```
Client                          Server
  │                               │
  ├─── TCP SYN ───────────────────>
  │                               │
  <──── TCP SYN-ACK ──────────────┤
  │                               │
  ├─── TCP ACK ───────────────────>
  │                               │ sig_listen() called
  │                               │ SSL channel created
  │                               │ client_input() registered
  │                               │
  ├─── SSL Client Hello ─────────>
  │                               │ SSL handshake
  <──── SSL Server Hello ─────────┤
  │     (+ Certificate)           │
  │                               │
  ├─── SSL Finished ─────────────>
  │                               │
  ├─── HTTP GET /?password=X ────>
  │     Upgrade: websocket        │ fe_web_handle_handshake()
  │     Sec-WebSocket-Key: ...    │ Verify password
  │                               │ Compute accept key
  <──── HTTP 101 ─────────────────┤
  │     Sec-WebSocket-Accept: ... │
  │                               │
  <──── WS Binary Frame ──────────┤
  │     (Encrypted auth_ok)       │
  │                               │
  ├─── WS Binary Frame ──────────>
  │     (Encrypted sync_server)   │
  │                               │ fe_web_client_handle_message()
  │                               │ fe_web_dump_state()
  <──── WS Binary Frames ─────────┤
  │     (Encrypted state dump)    │
  │                               │
```

---

### 3. fe-web-websocket.c - WebSocket Protocol

**Responsibilities:**
- Implement RFC 6455 WebSocket protocol
- Frame parsing and construction
- Payload masking/unmasking
- Sec-WebSocket-Accept computation

**WebSocket Frame Format:**

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               |Masking-key, if MASK set to 1  |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
```

**Opcodes:**

| Opcode | Meaning | Direction | Usage |
|--------|---------|-----------|-------|
| 0x0 | Continuation | Both | Fragmented messages (not used) |
| 0x1 | Text | Client→Server | Plain JSON (optional) |
| 0x2 | Binary | Both | Encrypted JSON (always used) |
| 0x8 | Close | Both | Connection termination |
| 0x9 | Ping | Client→Server | Keep-alive |
| 0xA | Pong | Server→Client | Ping response |

**Key Functions:**

```c
// Compute WebSocket accept key
char *fe_web_websocket_compute_accept(const char *key)
{
    // key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    // → SHA-1 hash → Base64 encode
}

// Parse incoming frame
int fe_web_websocket_parse_frame(
    const guchar *data, gsize len,
    gboolean *fin, guchar *opcode, gboolean *masked,
    guint64 *payload_len, guchar mask_key[4],
    const guchar **payload
)
{
    // Extract fields from frame header
    // Return: 1=complete, 0=incomplete, -1=error
}

// Unmask client payload
void fe_web_websocket_unmask(
    guchar *data, guint64 len,
    const guchar mask_key[4]
)
{
    // XOR each byte with mask_key[i % 4]
}

// Create outgoing frame
guchar *fe_web_websocket_create_frame(
    guchar opcode,
    const guchar *payload, guint64 payload_len,
    gsize *frame_len
)
{
    // Build frame with FIN=1, MASK=0
    // Server frames are never masked
}
```

---

### 4. fe-web-ssl.c/h - SSL/TLS Layer

**Responsibilities:**
- SSL/TLS encryption wrapper
- Self-signed certificate generation
- Non-blocking SSL operations
- SSL context management

**Certificate Generation:**

```c
void fe_web_ssl_init(void)
{
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    // Create SSL context
    global_ssl_ctx = SSL_CTX_new(SSLv23_server_method());

    // Generate RSA key (2048-bit)
    EVP_PKEY *pkey = generate_rsa_key();

    // Generate self-signed certificate (X.509v3, 10 years)
    X509 *cert = generate_self_signed_cert(pkey);

    // Load into context
    SSL_CTX_use_certificate(global_ssl_ctx, cert);
    SSL_CTX_use_PrivateKey(global_ssl_ctx, pkey);
}
```

**SSL Channel Operations:**

```
┌────────────────────────────────────────────┐
│          SSL Channel Lifecycle             │
├────────────────────────────────────────────┤
│                                            │
│  1. fe_web_ssl_channel_create()           │
│     ├─ SSL_new(global_ssl_ctx)            │
│     ├─ SSL_set_fd(ssl, fd)                │
│     └─ Return FE_WEB_SSL_CHANNEL          │
│                                            │
│  2. fe_web_ssl_accept() - Handshake       │
│     ├─ SSL_accept(ssl)                    │
│     ├─ Handle SSL_ERROR_WANT_READ/WRITE   │
│     └─ Return: 1=done, 0=more, -1=error   │
│                                            │
│  3. fe_web_ssl_read() - Read data         │
│     ├─ SSL_read(ssl, buf, len)            │
│     └─ Return: bytes, 0=closed, -1=error  │
│                                            │
│  4. fe_web_ssl_write() - Write data       │
│     ├─ SSL_write(ssl, buf, len)           │
│     └─ Return: bytes, -1=error            │
│                                            │
│  5. fe_web_ssl_channel_destroy()          │
│     ├─ SSL_shutdown(ssl)                  │
│     ├─ SSL_free(ssl)                      │
│     └─ close(fd)                          │
│                                            │
└────────────────────────────────────────────┘
```

---

### 5. fe-web-crypto.c/h - Encryption Layer

**Responsibilities:**
- AES-256-GCM encryption/decryption
- PBKDF2 key derivation
- IV generation
- Authentication tag verification

**Encryption Flow:**

```
Password (from fe_web_password setting)
    │
    ▼
┌───────────────────────────────────────┐
│  PBKDF2-HMAC-SHA256                   │
│  Salt: "irssi-fe-web-v1" (15 bytes)   │
│  Iterations: 10,000                   │
│  Output: 32 bytes (256 bits)          │
└───────────────┬───────────────────────┘
                │
                ▼
         AES-256 Key (32 bytes)
                │
    ┌───────────┴───────────┐
    │                       │
    ▼                       ▼
Encryption              Decryption
    │                       │
    ├─ Generate random IV   ├─ Extract IV (12B)
    │  (12 bytes)           │
    │                       │
    ├─ AES-256-GCM          ├─ AES-256-GCM
    │  Encrypt plaintext    │  Decrypt ciphertext
    │                       │
    ├─ Generate tag (16B)   ├─ Verify tag (16B)
    │                       │
    ▼                       ▼
[IV][Ciphertext][Tag]   Plaintext or ERROR
```

**Key Functions:**

```c
// Initialize crypto system
void fe_web_crypto_init(void)
{
    const char *password = settings_get_str("fe_web_password");
    fe_web_crypto_derive_key(password, global_key);
}

// Derive 256-bit key from password
void fe_web_crypto_derive_key(const char *password, unsigned char *key)
{
    PKCS5_PBKDF2_HMAC(
        password, strlen(password),
        (unsigned char *)"irssi-fe-web-v1", 15,
        10000,  // iterations
        EVP_sha256(),
        32,     // key length
        key
    );
}

// Encrypt message
int fe_web_crypto_encrypt(
    const unsigned char *plaintext, int plaintext_len,
    const unsigned char *key,
    unsigned char *ciphertext, int *ciphertext_len
)
{
    // Generate random IV (12 bytes)
    RAND_bytes(iv, 12);

    // Encrypt with AES-256-GCM
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext + 12, &len, plaintext, plaintext_len);
    EVP_EncryptFinal_ex(ctx, ciphertext + 12 + len, &len);

    // Get tag (16 bytes)
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + 12 + plaintext_len);

    // Format: [IV(12)][Ciphertext(N)][Tag(16)]
    memcpy(ciphertext, iv, 12);
}

// Decrypt message
int fe_web_crypto_decrypt(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *key,
    unsigned char *plaintext, int *plaintext_len
)
{
    // Extract IV, ciphertext, tag
    memcpy(iv, ciphertext, 12);
    memcpy(tag, ciphertext + ciphertext_len - 16, 16);

    // Decrypt with AES-256-GCM
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext + 12, ciphertext_len - 28);

    // Set expected tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    // Verify tag and finalize
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    // ret == 1: success, ret <= 0: authentication failed
}
```

---

### 6. fe-web-client.c - Request Dispatcher

**Responsibilities:**
- Client state management
- Message type routing
- Command execution
- Server subscription

**Client State Machine:**

```
┌─────────────────────────────────────────────────┐
│              Client State Machine               │
├─────────────────────────────────────────────────┤
│                                                 │
│  State: CREATED                                 │
│    ├─ fd, id, addr set                         │
│    ├─ authenticated = 0                         │
│    ├─ handshake_done = 0                        │
│    └─ SSL channel created                       │
│        │                                         │
│        ▼                                         │
│  State: HANDSHAKE_DONE                          │
│    ├─ handshake_done = 1                        │
│    ├─ authenticated = 1                         │
│    ├─ auth_ok message sent                      │
│    └─ Ready to receive messages                 │
│        │                                         │
│        ▼                                         │
│  State: SUBSCRIBED                              │
│    ├─ server != NULL (specific server)          │
│    │  OR wants_all_servers = 1                  │
│    ├─ Receiving events                          │
│    └─ Can send commands                         │
│        │                                         │
│        ▼                                         │
│  State: CLOSED                                  │
│    └─ Client destroyed                          │
│                                                 │
└─────────────────────────────────────────────────┘
```

**Message Dispatcher:**

```c
void fe_web_client_handle_message(WEB_CLIENT_REC *client, const char *json)
{
    char *type = fe_web_json_get_string(json, "type");

    if (strcmp(type, "sync_server") == 0) {
        fe_web_client_sync_server(client, json);
    }
    else if (strcmp(type, "command") == 0) {
        fe_web_client_execute_command(client, json);
    }
    else if (strcmp(type, "ping") == 0) {
        fe_web_send_pong(client);
    }
    else if (strcmp(type, "close_query") == 0) {
        fe_web_client_close_query(client, json);
    }
    else if (strcmp(type, "names") == 0) {
        fe_web_client_execute_names(client, json);
    }
    else if (strcmp(type, "mark_read") == 0) {
        fe_web_client_mark_read(client, json);
    }
    else if (strcmp(type, "network_list") == 0) {
        fe_web_handle_network_list(client);
    }
    else if (strcmp(type, "network_add") == 0) {
        fe_web_handle_network_add(client, json);
    }
    else if (strcmp(type, "network_remove") == 0) {
        fe_web_handle_network_remove(client, json);
    }
    else if (strcmp(type, "server_list") == 0) {
        fe_web_handle_server_list(client);
    }
    else if (strcmp(type, "server_add") == 0) {
        fe_web_handle_server_add(client, json);
    }
    else if (strcmp(type, "server_remove") == 0) {
        fe_web_handle_server_remove(client, json);
    }

    g_free(type);
}
```

---

### 7. fe-web-signals.c - IRC Event Handlers

**Responsibilities:**
- Listen to irssi signal emissions
- Convert IRC events to web messages
- Broadcast to relevant clients
- Manage WHOIS state

**Signal Registration:**

```c
void fe_web_signals_init(void)
{
    // Message signals
    signal_add_first("message public", (SIGNAL_FUNC) sig_message_public);
    signal_add_first("message private", (SIGNAL_FUNC) sig_message_private);
    signal_add_first("message own_public", (SIGNAL_FUNC) sig_message_own_public);
    signal_add_first("message own_private", (SIGNAL_FUNC) sig_message_own_private);
    signal_add_first("message irc action", (SIGNAL_FUNC) sig_message_irc_action);
    signal_add_first("message irc own_action", (SIGNAL_FUNC) sig_message_irc_own_action);

    // Channel events
    signal_add("message join", (SIGNAL_FUNC) sig_message_join);
    signal_add("message part", (SIGNAL_FUNC) sig_message_part);
    signal_add("message kick", (SIGNAL_FUNC) sig_message_kick);
    signal_add("message quit", (SIGNAL_FUNC) sig_message_quit);
    signal_add("message topic", (SIGNAL_FUNC) sig_message_topic);
    signal_add("message irc mode", (SIGNAL_FUNC) sig_message_mode);

    // Nick changes
    signal_add("message nick", (SIGNAL_FUNC) sig_nick_changed);
    signal_add("message own_nick", (SIGNAL_FUNC) sig_message_own_nick);

    // Server events
    signal_add("server connected", (SIGNAL_FUNC) sig_server_connected);
    signal_add("server disconnected", (SIGNAL_FUNC) sig_server_disconnected);
    signal_add("event away", (SIGNAL_FUNC) sig_server_away);

    // WHOIS events
    signal_add("event 311", (SIGNAL_FUNC) event_whois);
    signal_add("event 312", (SIGNAL_FUNC) event_whois_server);
    signal_add("event 317", (SIGNAL_FUNC) event_whois_idle);
    signal_add("event 319", (SIGNAL_FUNC) event_whois_channels);
    signal_add("event 330", (SIGNAL_FUNC) event_whois_account);
    signal_add("event 671", (SIGNAL_FUNC) event_whois_secure);
    signal_add("event 313", (SIGNAL_FUNC) event_whois_oper);

    // Activity tracking
    signal_add("window activity", (SIGNAL_FUNC) sig_window_activity);
    signal_add("window hilight", (SIGNAL_FUNC) sig_window_hilight);
    signal_add("window item remove", (SIGNAL_FUNC) sig_window_item_remove);
}
```

**Signal Handler Pattern:**

```c
static void sig_message_public(
    IRC_SERVER_REC *server,
    const char *msg,
    const char *nick,
    const char *address,
    const char *target
)
{
    // Create web message
    WEB_MESSAGE_REC *web_msg = fe_web_message_new(WEB_MSG_MESSAGE);
    web_msg->server_tag = g_strdup(server->tag);
    web_msg->target = g_strdup(target);
    web_msg->nick = g_strdup(nick);
    web_msg->text = g_strdup(msg);
    web_msg->level = MSGLEVEL_PUBLIC;
    web_msg->is_own = FALSE;

    // Check for highlight
    HILIGHT_REC *hilight = hilight_match(SERVER(server), target, nick,
                                         address, MSGLEVEL_PUBLIC, msg,
                                         NULL, NULL);
    web_msg->is_highlight = (hilight != NULL);

    // Add extra data
    if (address)
        g_hash_table_insert(web_msg->extra_data, g_strdup("hostname"),
                          g_strdup(address));

    // Send to all clients subscribed to this server
    fe_web_send_to_server_clients(server, web_msg);

    // Clean up
    fe_web_message_free(web_msg);
}
```

---

## Data Flow

### Incoming Message Flow (Client → Server → irssi)

```
┌───────────────────────────────────────────────────────────┐
│  1. Client sends encrypted WebSocket binary frame         │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  2. TCP → SSL_read() → client_input()                     │
│     Data accumulated in input_buffer                      │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  3. fe_web_handle_websocket_data()                        │
│     Parse WebSocket frame (opcode 0x2 = binary)           │
│     Unmask payload with client's mask key                 │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  4. fe_web_crypto_decrypt()                               │
│     Extract IV (12B), ciphertext, tag (16B)               │
│     AES-256-GCM decrypt with derived key                  │
│     Verify authentication tag                             │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
         Decrypted JSON string
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  5. fe_web_client_handle_message()                        │
│     Parse "type" field                                    │
│     Route to appropriate handler                          │
└────────────────┬──────────────────────────────────────────┘
                 │
         ┌───────┴───────┐
         │               │
         ▼               ▼
┌─────────────────┐  ┌──────────────────────────┐
│  6a. Command    │  │  6b. Other handlers      │
│  Execute IRC    │  │  • mark_read             │
│  command via    │  │  • sync_server           │
│  signal_emit()  │  │  • network_add           │
└─────────────────┘  │  • etc.                  │
                     └──────────────────────────┘
```

### Outgoing Message Flow (irssi → Server → Client)

```
┌───────────────────────────────────────────────────────────┐
│  1. irssi emits signal (e.g., "message public")           │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  2. Signal handler (e.g., sig_message_public)             │
│     Create WEB_MESSAGE_REC                                │
│     Populate fields from signal parameters                │
│     Add extra data (hostname, etc.)                       │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  3. fe_web_send_to_server_clients()                       │
│     For each client in web_clients:                       │
│       If authenticated AND subscribed to server:          │
│         Call fe_web_send_message()                        │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  4. fe_web_message_to_json()                              │
│     Serialize WEB_MESSAGE_REC to JSON string              │
│     Escape special characters                             │
│     Format nested JSON for extra data                     │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
         JSON string
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  5. fe_web_crypto_encrypt()                               │
│     Generate random IV (12 bytes)                         │
│     AES-256-GCM encrypt JSON                              │
│     Extract authentication tag (16 bytes)                 │
│     Format: [IV][Ciphertext][Tag]                         │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
   Encrypted binary data
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  6. fe_web_websocket_create_frame()                       │
│     Create binary frame (opcode 0x2)                      │
│     FIN=1, MASK=0 (server doesn't mask)                   │
│     Add payload length encoding                           │
└────────────────┬──────────────────────────────────────────┘
                 │
                 ▼
   WebSocket frame
                 │
                 ▼
┌───────────────────────────────────────────────────────────┐
│  7. SSL_write() → TCP → Client                            │
└───────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Defense in Depth

The module implements multiple security layers:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Network Security                             │
│  • Bind to localhost (127.0.0.1) by default            │
│  • Firewall rules recommended                          │
│  • No fallback to insecure connections                 │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Layer 2: Transport Security (TLS/SSL)                 │
│  • wss:// protocol (WebSocket Secure)                  │
│  • TLS 1.2+ (SSLv23 method)                            │
│  • 2048-bit RSA keys                                   │
│  • X.509v3 certificates                                │
│  • Perfect Forward Secrecy (depending on cipher suite) │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Layer 3: Authentication                               │
│  • Password required in handshake                      │
│  • Password verified before connection accepted        │
│  • Connection terminates on auth failure               │
│  • No retry mechanism (prevent brute force)            │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Layer 4: Application Encryption (AES-256-GCM)         │
│  • All messages encrypted (even over TLS)              │
│  • Authenticated encryption (detects tampering)        │
│  • 256-bit keys (quantum-resistant for now)            │
│  • Random IV per message (prevents replay)             │
│  • 16-byte authentication tag (prevents forgery)       │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│  Layer 5: Input Validation                             │
│  • JSON parsing with error handling                    │
│  • Type checking for message fields                    │
│  • Length limits on inputs                             │
│  • Escaping of special characters                      │
└─────────────────────────────────────────────────────────┘
```

### Threat Model

**Protected Against:**
- ✅ Network eavesdropping (TLS/SSL)
- ✅ Man-in-the-middle attacks (TLS/SSL + AES-GCM)
- ✅ Message tampering (AES-GCM authentication tag)
- ✅ Replay attacks (random IV per message)
- ✅ Unauthorized access (password authentication)
- ✅ JSON injection (proper escaping)

**Potential Vulnerabilities:**
- ⚠️ Self-signed certificates (MITM on first connect)
- ⚠️ No rate limiting (brute force, DoS)
- ⚠️ Fixed PBKDF2 salt (rainbow tables if password leaked)
- ⚠️ No session expiration (persistent access)
- ⚠️ No IP whitelisting (password is single factor)

**Recommendations:**
- Use proper SSL certificates (Let's Encrypt)
- Implement rate limiting
- Add IP whitelisting option
- Add session timeout
- Use random salt per installation
- Add two-factor authentication

---

## Module Lifecycle

### Initialization Sequence

```
1. irssi loads module (dlopen)
   │
   ▼
2. module_init() called
   │
   ▼
3. fe_web_init()
   ├─ Register settings
   ├─ Register commands
   ├─ fe_web_signals_init()
   │  └─ Register 55+ signal handlers
   ├─ fe_web_ssl_init()
   │  ├─ Initialize OpenSSL
   │  ├─ Generate RSA key
   │  └─ Generate self-signed certificate
   ├─ fe_web_crypto_init()
   │  └─ Derive AES key from password
   └─ If fe_web_enabled:
      └─ fe_web_server_init()
         ├─ Create listening socket
         ├─ Bind to address:port
         ├─ Listen for connections
         └─ Register accept handler
```

### Runtime Behavior

```
Main Event Loop (irssi)
│
├─ TCP accept event
│  └─ sig_listen() → Create client
│
├─ Socket read event
│  └─ client_input() → Process data
│
├─ IRC event (e.g., message received)
│  └─ Signal handler → Send to web clients
│
├─ Timer event (none currently)
│
└─ User input (e.g., /FE_WEB STATUS)
   └─ cmd_fe_web() → Display status
```

### Shutdown Sequence

```
1. User types /UNLOAD fe-web
   │
   ▼
2. module_deinit() called
   │
   ▼
3. fe_web_deinit()
   ├─ fe_web_server_deinit()
   │  ├─ Close listening socket
   │  └─ For each client:
   │     └─ fe_web_close_client()
   ├─ fe_web_crypto_deinit()
   │  └─ Clear encryption key
   ├─ fe_web_ssl_deinit()
   │  ├─ Free SSL context
   │  └─ Cleanup OpenSSL
   ├─ fe_web_signals_deinit()
   │  └─ Unregister signal handlers
   ├─ Unregister commands
   └─ Unregister settings
```

---

## Signal System

### irssi Signal Architecture

irssi uses a publish-subscribe signal system for loose coupling between modules.

**Signal Flow:**

```
IRC Event
   │
   ▼
irssi Core
   │
   ├─ Parse IRC message
   ├─ Update internal state
   └─ signal_emit("signal name", params...)
      │
      ▼
   ┌──────────────────────────────────────┐
   │  Signal Dispatcher                   │
   │  For each registered handler:        │
   │    Call handler(params...)           │
   └──────────────────────────────────────┘
      │
      ├─ Handler 1 (fe-web)
      ├─ Handler 2 (other module)
      └─ Handler N (other module)
```

### fe-web Signal Usage

**Example: Public Message**

```
1. User sends message on IRC
   │
   ▼
2. irssi receives: ":alice!~a@host PRIVMSG #channel :Hello"
   │
   ▼
3. irssi parses and emits:
   signal_emit("message public", server, "Hello", "alice",
               "~a@host", "#channel");
   │
   ▼
4. fe-web handler (sig_message_public) receives params
   │
   ▼
5. Create WEB_MESSAGE_REC
   │
   ▼
6. fe_web_send_to_server_clients(server, msg)
   │
   ▼
7. For each authenticated client subscribed to server:
   └─ Serialize → Encrypt → Send
```

---

## State Management

### Client State

Each connected client maintains state in `WEB_CLIENT_REC`:

```c
typedef struct {
    // Connection
    int fd;
    char *id;                   // "client-{timestamp}-{counter}"
    char *addr;                 // "127.0.0.1:12345"
    time_t connected_at;

    // Authentication
    unsigned authenticated : 1;
    unsigned handshake_done : 1;
    char *websocket_key;

    // Server subscription
    IRC_SERVER_REC *server;     // NULL or specific server
    unsigned wants_all_servers : 1;
    GSList *synced_channels;    // List of channel names

    // Network I/O
    NET_SENDBUF_REC *handle;
    GString *output_buffer;
    GByteArray *input_buffer;
    int recv_tag;

    // Security
    FE_WEB_SSL_CHANNEL *ssl_channel;
    unsigned use_ssl : 1;
    unsigned encryption_enabled : 1;

    // Statistics
    unsigned long messages_sent;
    unsigned long messages_received;

    // Request tracking
    GHashTable *pending_requests;
} WEB_CLIENT_REC;
```

### Server State

The module maintains minimal global state:

```c
// Global variables (static in fe-web-server.c)
static GIOChannel *listen_channel = NULL;
static int listen_tag = -1;
static int listen_fd = -1;
static GSList *web_clients = NULL;  // List of WEB_CLIENT_REC*

// SSL context (static in fe-web-ssl.c)
static SSL_CTX *global_ssl_ctx = NULL;

// Encryption key (static in fe-web-crypto.c)
static unsigned char global_key[32];

// WHOIS tracking (static in fe-web-signals.c)
static GHashTable *active_whois = NULL;  // key → WHOIS_REC*
```

---

## Performance Considerations

### Message Routing Efficiency

**Broadcast Optimization:**

```c
// Bad: Serialize once per client
for (client in clients) {
    json = fe_web_message_to_json(msg);  // Repeated work
    send(client, json);
    g_free(json);
}

// Good: Serialize once, send to all
json = fe_web_message_to_json(msg);
for (client in clients) {
    send(client, json);
}
g_free(json);
```

**Current implementation:** Messages are serialized once per client due to encryption (each client needs a unique IV). This is cryptographically necessary but has performance cost.

**Potential optimization:** Use same JSON, different IVs:

```c
json = fe_web_message_to_json(msg);
for (client in clients) {
    encrypted = encrypt_with_random_iv(json, client->key);
    send(client, encrypted);
    g_free(encrypted);
}
g_free(json);
```

### Buffer Management

**Send Buffer:**
- irssi's `NET_SENDBUF_REC` handles buffering
- Configurable size: 2MB (set in `fe_web_server_init()`)
- Prevents blocking on slow clients

**Receive Buffer:**
- `GByteArray *input_buffer` accumulates partial frames
- Grows dynamically as needed
- Cleared after frame processed
- Memory limit: None (potential DoS vector)

**Optimization:** Add maximum buffer size limit:

```c
#define MAX_INPUT_BUFFER_SIZE (1024 * 1024)  // 1MB

if (client->input_buffer->len > MAX_INPUT_BUFFER_SIZE) {
    fe_web_close_client(client);
    return;
}
```

### Encryption Performance

**Benchmark estimates:**
- PBKDF2 (10,000 iterations): ~10ms (one-time on startup)
- AES-256-GCM encrypt/decrypt: ~0.1ms per message
- Overhead: ~5-10% compared to plain JSON

**Bottleneck:** PBKDF2 is CPU-intensive but only runs once.

---

## Extension Points

### Adding New Message Types

**1. Define type in `fe-web.h`:**

```c
typedef enum {
    // ... existing types
    WEB_MSG_YOUR_NEW_TYPE = 100,
} WEB_MESSAGE_TYPE;
```

**2. Add signal handler in `fe-web-signals.c`:**

```c
static void sig_your_event(/* irssi signal params */)
{
    WEB_MESSAGE_REC *msg = fe_web_message_new(WEB_MSG_YOUR_NEW_TYPE);
    msg->server_tag = g_strdup(server->tag);
    msg->text = g_strdup(event_data);
    // ... populate other fields

    fe_web_send_to_server_clients(server, msg);
    fe_web_message_free(msg);
}

void fe_web_signals_init(void)
{
    // ... existing registrations
    signal_add("your event name", (SIGNAL_FUNC) sig_your_event);
}
```

**3. Handle in client (optional):**

If client can send this message type:

```c
void fe_web_client_handle_message(WEB_CLIENT_REC *client, const char *json)
{
    // ... existing handlers
    else if (strcmp(type, "your_message_type") == 0) {
        fe_web_client_handle_your_type(client, json);
    }
}
```

**4. Update documentation:**
- README.md
- API.md
- This file (ARCHITECTURE.md)

### Adding New Settings

**1. Register in `fe_web_init()`:**

```c
settings_add_str("lookandfeel", "fe_web_your_setting", "default_value");
```

**2. Use in code:**

```c
const char *value = settings_get_str("fe_web_your_setting");
int num = settings_get_int("fe_web_your_setting");
gboolean flag = settings_get_bool("fe_web_your_setting");
```

**3. Watch for changes:**

```c
static void fe_web_setup_changed(void)
{
    const char *new_value = settings_get_str("fe_web_your_setting");
    // React to change
}

// In fe_web_init():
signal_add("setup changed", (SIGNAL_FUNC) fe_web_setup_changed);
```

### Adding New Client Commands

**1. Add handler in `fe-web-client.c`:**

```c
static void fe_web_client_handle_your_command(WEB_CLIENT_REC *client, const char *json)
{
    char *param = fe_web_json_get_string(json, "param");

    // Do something with param

    g_free(param);
}
```

**2. Register in dispatcher:**

```c
void fe_web_client_handle_message(WEB_CLIENT_REC *client, const char *json)
{
    // ... existing handlers
    else if (strcmp(type, "your_command") == 0) {
        fe_web_client_handle_your_command(client, json);
    }
}
```

---

## Conclusion

The irssi-fe-web module is a well-architected, secure, and extensible system for bridging IRC and the web. Its layered design ensures separation of concerns, while its use of industry-standard encryption and authentication protocols provides strong security guarantees.

Key strengths:
- **Clean architecture** with clear component boundaries
- **Defense in depth** security model
- **RFC-compliant** WebSocket implementation
- **Extensible** signal-based design
- **Efficient** message routing and buffering

Areas for improvement:
- Rate limiting and DoS protection
- Session management and timeout
- IPv6 support
- Compression support
- Unit test coverage

For developers extending this module, the signal system provides natural extension points, while the message-based protocol makes it easy to add new functionality without breaking existing clients.
