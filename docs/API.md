# WebSocket API Documentation

## Table of Contents

- [Overview](#overview)
- [Connection](#connection)
  - [WebSocket Handshake](#websocket-handshake)
  - [Authentication](#authentication)
  - [Encryption](#encryption)
- [Message Format](#message-format)
- [Client to Server Messages](#client-to-server-messages)
- [Server to Client Messages](#server-to-client-messages)
- [Message Type Reference](#message-type-reference)
- [Data Structures](#data-structures)
- [Error Handling](#error-handling)
- [Examples](#examples)

---

## Overview

The irssi-fe-web WebSocket API provides real-time bidirectional communication between irssi and web clients. All messages are JSON-formatted and transmitted over encrypted WebSocket connections (wss://).

### Protocol Stack

```
┌──────────────────────────────────────┐
│   JSON Message Protocol              │  Application Layer
├──────────────────────────────────────┤
│   AES-256-GCM Encryption             │  Encryption Layer
├──────────────────────────────────────┤
│   WebSocket Protocol (RFC 6455)      │  Transport Layer
├──────────────────────────────────────┤
│   TLS/SSL (wss://)                   │  Security Layer
├──────────────────────────────────────┤
│   TCP/IP                             │  Network Layer
└──────────────────────────────────────┘
```

### Key Characteristics

- **Protocol**: WebSocket (RFC 6455)
- **Transport**: wss:// (WebSocket Secure)
- **Encryption**: TLS/SSL + AES-256-GCM
- **Format**: JSON
- **Authentication**: Password-based
- **Encoding**: UTF-8

---

## Connection

### WebSocket Handshake

**1. Establish WebSocket Connection**

```javascript
const password = 'your_secure_password';
const ws = new WebSocket(`wss://localhost:9001/?password=${encodeURIComponent(password)}`);
```

**2. HTTP Request (Client → Server)**

```http
GET /?password=your_secure_password HTTP/1.1
Host: localhost:9001
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

**3. HTTP Response (Server → Client)**

```http
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

**4. Authentication Confirmation**

After successful handshake, server sends:

```json
{
    "type": "auth_ok",
    "timestamp": 1737000000
}
```

### Authentication

**Password Requirements:**
- **Location**: URL query parameter (`?password=...`)
- **Encoding**: URL-encoded (use `encodeURIComponent()` in JavaScript)
- **Validation**: Must match configured `fe_web_password` setting
- **Failure**: Connection terminates immediately

**Example with Special Characters:**

```javascript
const password = 'p@ssw0rd!#$';
const encodedPassword = encodeURIComponent(password);
const ws = new WebSocket(`wss://localhost:9001/?password=${encodedPassword}`);
```

### Encryption

All messages (except initial handshake) are encrypted using AES-256-GCM.

**Encrypted Message Structure:**

```
┌──────────────┬────────────────────┬──────────────┐
│   IV (12B)   │   Ciphertext (N)   │   Tag (16B)  │
└──────────────┴────────────────────┴──────────────┘
```

**Encryption Parameters:**
- **Algorithm**: AES-256-GCM
- **Key Size**: 32 bytes (256 bits)
- **IV Size**: 12 bytes (random per message)
- **Tag Size**: 16 bytes (authentication)
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 10,000
- **Salt**: "irssi-fe-web-v1" (15 bytes)

**JavaScript Decryption Example:**

```javascript
async function decryptMessage(encryptedData, password) {
    // Derive key from password
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const salt = encoder.encode('irssi-fe-web-v1');
    const keyMaterial = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 10000,
            hash: 'SHA-256'
        },
        passwordKey,
        256  // 32 bytes * 8
    );

    const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        'AES-GCM',
        false,
        ['decrypt']
    );

    // Extract IV, ciphertext, and tag
    const data = new Uint8Array(encryptedData);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12, -16);
    const tag = data.slice(-16);

    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        },
        key,
        new Uint8Array([...ciphertext, ...tag])
    );

    return new TextDecoder().decode(decrypted);
}

// Usage
ws.onmessage = async (event) => {
    if (event.data instanceof Blob) {
        const buffer = await event.data.arrayBuffer();
        const json = await decryptMessage(buffer, password);
        const message = JSON.parse(json);
        console.log('Received:', message);
    }
};
```

**JavaScript Encryption Example:**

```javascript
async function encryptMessage(json, password) {
    // Derive key (same as decryption)
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const salt = encoder.encode('irssi-fe-web-v1');
    const keyMaterial = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 10000,
            hash: 'SHA-256'
        },
        passwordKey,
        256
    );

    const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        'AES-GCM',
        false,
        ['encrypt']
    );

    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Encrypt
    const plaintext = encoder.encode(json);
    const encrypted = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        },
        key,
        plaintext
    );

    // Combine IV + ciphertext + tag
    const result = new Uint8Array(12 + encrypted.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(encrypted), 12);

    return result;
}

// Usage
const message = JSON.stringify({ type: 'ping' });
const encrypted = await encryptMessage(message, password);
ws.send(encrypted);
```

---

## Message Format

### Common Fields

All messages share these common fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Message type identifier |
| `id` | string | No | Unique message ID (format: `{timestamp}-{counter}`) |
| `timestamp` | integer | No | Unix timestamp (seconds since epoch) |
| `server` | string | No | IRC server tag |
| `channel` | string | No | Channel name (with # prefix) |
| `nick` | string | No | User nickname |
| `text` | string | No | Message text content |

### Message ID Format

```
{unix_timestamp}-{counter}

Examples:
1737000000-0001
1737000001-0002
1737000002-0003
```

- **Timestamp**: Unix timestamp in seconds
- **Counter**: 4-digit sequential counter (0001-9999, wraps around)

---

## Client to Server Messages

Messages sent from the web client to irssi.

### 1. Server Subscription

Subscribe to receive events from a specific server or all servers.

**Message Type:** `sync_server`

**Fields:**
- `type` (string, required): `"sync_server"`
- `server` (string, required): Server tag or `"*"` for all servers

**Examples:**

```json
{
    "type": "sync_server",
    "server": "freenode"
}
```

```json
{
    "type": "sync_server",
    "server": "*"
}
```

**Response:** Server sends complete state dump including:
- Server status
- Channel topics
- Nicklists
- Query windows
- Activity status

---

### 2. Execute IRC Command

Execute an IRC command on the server.

**Message Type:** `command`

**Fields:**
- `type` (string, required): `"command"`
- `server` (string, required): Server tag
- `command` (string, required): IRC command to execute

**Examples:**

**Send a message:**
```json
{
    "type": "command",
    "server": "freenode",
    "command": "PRIVMSG #channel :Hello, world!"
}
```

**Join a channel:**
```json
{
    "type": "command",
    "server": "freenode",
    "command": "JOIN #new-channel"
}
```

**Change nick:**
```json
{
    "type": "command",
    "server": "freenode",
    "command": "NICK new_nickname"
}
```

**Set away:**
```json
{
    "type": "command",
    "server": "freenode",
    "command": "AWAY :Gone for lunch"
}
```

**Query WHOIS:**
```json
{
    "type": "command",
    "server": "freenode",
    "command": "WHOIS alice"
}
```

---

### 3. Ping

Keep-alive message to maintain connection.

**Message Type:** `ping`

**Fields:**
- `type` (string, required): `"ping"`

**Example:**

```json
{
    "type": "ping"
}
```

**Response:**

```json
{
    "type": "pong",
    "timestamp": 1737000000
}
```

---

### 4. Close Query Window

Close a private message (query) window.

**Message Type:** `close_query`

**Fields:**
- `type` (string, required): `"close_query"`
- `server` (string, required): Server tag
- `nick` (string, required): Nick of query to close

**Example:**

```json
{
    "type": "close_query",
    "server": "freenode",
    "nick": "alice"
}
```

---

### 5. Request Channel Names

Request the user list (NAMES) for a channel.

**Message Type:** `names`

**Fields:**
- `type` (string, required): `"names"`
- `server` (string, required): Server tag
- `channel` (string, required): Channel name

**Example:**

```json
{
    "type": "names",
    "server": "freenode",
    "channel": "#channel"
}
```

**Response:** Server sends `nicklist` message with full user list.

---

### 6. Mark as Read

Clear activity markers for a channel or query.

**Message Type:** `mark_read`

**Fields:**
- `type` (string, required): `"mark_read"`
- `server` (string, required): Server tag
- `channel` (string, required): Channel or nick name

**Example:**

```json
{
    "type": "mark_read",
    "server": "freenode",
    "channel": "#channel"
}
```

**Response:** Server sends `activity_update` with level 0.

---

### 7. Network Management

#### 7.1 List Networks

Request list of all configured networks.

**Message Type:** `network_list`

**Fields:**
- `type` (string, required): `"network_list"`

**Example:**

```json
{
    "type": "network_list"
}
```

**Response:** Server sends `network_list_response`.

---

#### 7.2 Add/Modify Network

Add or modify a network configuration.

**Message Type:** `network_add`

**Fields:**
- `type` (string, required): `"network_add"`
- `name` (string, required): Network name
- `nick` (string, optional): Default nickname
- `username` (string, optional): Username/ident
- `realname` (string, optional): Real name
- `autosendcmd` (string, optional): Commands to send on connect

**Example:**

```json
{
    "type": "network_add",
    "name": "freenode",
    "nick": "mynick",
    "username": "myuser",
    "realname": "My Real Name",
    "autosendcmd": "/msg NickServ identify password"
}
```

**Response:** Server sends `command_result`.

---

#### 7.3 Remove Network

Remove a network configuration.

**Message Type:** `network_remove`

**Fields:**
- `type` (string, required): `"network_remove"`
- `name` (string, required): Network name

**Example:**

```json
{
    "type": "network_remove",
    "name": "oldnetwork"
}
```

**Response:** Server sends `command_result`.

---

### 8. Server Management

#### 8.1 List Servers

Request list of all configured servers.

**Message Type:** `server_list`

**Fields:**
- `type` (string, required): `"server_list"`

**Example:**

```json
{
    "type": "server_list"
}
```

**Response:** Server sends `server_list_response`.

---

#### 8.2 Add/Modify Server

Add or modify a server configuration.

**Message Type:** `server_add`

**Fields:**
- `type` (string, required): `"server_add"`
- `name` (string, required): Server identifier
- `host` (string, required): Hostname or IP
- `port` (integer, required): Port number
- `chatnet` (string, optional): Associated network name
- `use_tls` (boolean, optional): Use SSL/TLS
- `autoconnect` (boolean, optional): Auto-connect on startup

**Example:**

```json
{
    "type": "server_add",
    "name": "irc.freenode.net",
    "host": "irc.freenode.net",
    "port": 6697,
    "chatnet": "freenode",
    "use_tls": true,
    "autoconnect": true
}
```

**Response:** Server sends `command_result`.

---

#### 8.3 Remove Server

Remove a server configuration.

**Message Type:** `server_remove`

**Fields:**
- `type` (string, required): `"server_remove"`
- `name` (string, required): Server identifier

**Example:**

```json
{
    "type": "server_remove",
    "name": "old.server.net"
}
```

**Response:** Server sends `command_result`.

---

## Server to Client Messages

Messages sent from irssi to the web client.

### 1. Authentication Success

Sent immediately after successful WebSocket handshake and password verification.

**Message Type:** `auth_ok`

**Fields:**
- `type` (string): `"auth_ok"`
- `timestamp` (integer): Unix timestamp

**Example:**

```json
{
    "type": "auth_ok",
    "timestamp": 1737000000
}
```

---

### 2. Chat Messages

#### 2.1 Public/Private Message

**Message Type:** `message`

**Fields:**
- `id` (string): Unique message ID
- `type` (string): `"message"`
- `server` (string): Server tag
- `channel` (string): Channel name or nick (for private messages)
- `nick` (string): Sender nickname
- `text` (string): Message text
- `timestamp` (integer): Unix timestamp
- `level` (integer): Message level (see [Message Levels](#message-levels))
- `is_own` (boolean): True if message is from the user
- `is_highlight` (boolean): True if message mentions the user
- `extra` (object, optional): Additional metadata

**Example (Public Message):**

```json
{
    "id": "1737000000-0001",
    "type": "message",
    "server": "freenode",
    "channel": "#channel",
    "nick": "alice",
    "text": "Hello, everyone!",
    "timestamp": 1737000000,
    "level": 4,
    "is_own": false,
    "is_highlight": false
}
```

**Example (Highlight):**

```json
{
    "id": "1737000000-0002",
    "type": "message",
    "server": "freenode",
    "channel": "#channel",
    "nick": "bob",
    "text": "Hey mynick, how are you?",
    "timestamp": 1737000001,
    "level": 4,
    "is_own": false,
    "is_highlight": true
}
```

**Example (Private Message):**

```json
{
    "id": "1737000000-0003",
    "type": "message",
    "server": "freenode",
    "channel": "alice",
    "nick": "alice",
    "text": "Private message for you",
    "timestamp": 1737000002,
    "level": 2,
    "is_own": false,
    "is_highlight": false
}
```

**Example (Own Message):**

```json
{
    "id": "1737000000-0004",
    "type": "message",
    "server": "freenode",
    "channel": "#channel",
    "nick": "mynick",
    "text": "This is my message",
    "timestamp": 1737000003,
    "level": 4,
    "is_own": true,
    "is_highlight": false
}
```

---

#### 2.2 ACTION Message (/me)

**Message Type:** `message`

**Fields:** Same as regular message, but `level` includes `MSGLEVEL_ACTIONS` flag.

**Example:**

```json
{
    "id": "1737000000-0005",
    "type": "message",
    "server": "freenode",
    "channel": "#channel",
    "nick": "alice",
    "text": "waves hello",
    "timestamp": 1737000004,
    "level": 132,
    "is_own": false,
    "is_highlight": false
}
```

**Detecting ACTION messages:**
```javascript
const MSGLEVEL_ACTIONS = 128;
const isAction = (message.level & MSGLEVEL_ACTIONS) !== 0;
```

---

### 3. Channel Events

#### 3.1 User Joined Channel

**Message Type:** `channel_join`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"channel_join"`
- `server` (string): Server tag
- `channel` (string): Channel name
- `nick` (string): User who joined
- `timestamp` (integer): Unix timestamp
- `extra` (object): Additional data
  - `hostname` (string): User's hostname (user@host)
  - `account` (string, optional): Account name (IRCv3)
  - `realname` (string, optional): Real name

**Example:**

```json
{
    "id": "1737000000-0006",
    "type": "channel_join",
    "server": "freenode",
    "channel": "#channel",
    "nick": "alice",
    "timestamp": 1737000005,
    "extra": {
        "hostname": "alice!~alice@example.com",
        "account": "alice_account",
        "realname": "Alice Smith"
    }
}
```

---

#### 3.2 User Left Channel

**Message Type:** `channel_part`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"channel_part"`
- `server` (string): Server tag
- `channel` (string): Channel name
- `nick` (string): User who left
- `text` (string, optional): Part message
- `timestamp` (integer): Unix timestamp
- `extra` (object): Additional data
  - `hostname` (string): User's hostname
  - `reason` (string, optional): Part reason

**Example:**

```json
{
    "id": "1737000000-0007",
    "type": "channel_part",
    "server": "freenode",
    "channel": "#channel",
    "nick": "bob",
    "text": "Goodbye!",
    "timestamp": 1737000006,
    "extra": {
        "hostname": "bob!~bob@example.com",
        "reason": "Goodbye!"
    }
}
```

---

#### 3.3 User Kicked from Channel

**Message Type:** `channel_kick`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"channel_kick"`
- `server` (string): Server tag
- `channel` (string): Channel name
- `nick` (string): User who was kicked
- `text` (string, optional): Kick reason
- `timestamp` (integer): Unix timestamp
- `extra` (object): Additional data
  - `kicker` (string): User who performed the kick
  - `reason` (string, optional): Kick reason
  - `hostname` (string): Kicked user's hostname

**Example:**

```json
{
    "id": "1737000000-0008",
    "type": "channel_kick",
    "server": "freenode",
    "channel": "#channel",
    "nick": "troublemaker",
    "text": "Spamming",
    "timestamp": 1737000007,
    "extra": {
        "kicker": "op_user",
        "reason": "Spamming",
        "hostname": "troublemaker!~user@example.com"
    }
}
```

---

#### 3.4 Topic Changed

**Message Type:** `topic`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"topic"`
- `server` (string): Server tag
- `channel` (string): Channel name
- `nick` (string): User who set the topic
- `text` (string): New topic
- `timestamp` (integer): Unix timestamp

**Example:**

```json
{
    "id": "1737000000-0009",
    "type": "topic",
    "server": "freenode",
    "channel": "#channel",
    "nick": "op_user",
    "text": "Welcome to #channel | Rules: https://example.com/rules",
    "timestamp": 1737000008
}
```

---

#### 3.5 Channel Mode Changed

**Message Type:** `channel_mode`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"channel_mode"`
- `server` (string): Server tag
- `channel` (string): Channel name
- `nick` (string): User who set the mode
- `text` (string): Mode change
- `timestamp` (integer): Unix timestamp

**Example:**

```json
{
    "id": "1737000000-0010",
    "type": "channel_mode",
    "server": "freenode",
    "channel": "#channel",
    "nick": "op_user",
    "text": "+m",
    "timestamp": 1737000009
}
```

---

### 4. User Events

#### 4.1 Nick Change

**Message Type:** `nick_change`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"nick_change"`
- `server` (string): Server tag
- `nick` (string): Old nickname
- `text` (string): New nickname
- `timestamp` (integer): Unix timestamp

**Example:**

```json
{
    "id": "1737000000-0011",
    "type": "nick_change",
    "server": "freenode",
    "nick": "alice",
    "text": "alice_away",
    "timestamp": 1737000010
}
```

---

#### 4.2 User Quit

**Message Type:** `user_quit`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"user_quit"`
- `server` (string): Server tag
- `nick` (string): User who quit
- `text` (string, optional): Quit message
- `timestamp` (integer): Unix timestamp
- `extra` (object): Additional data
  - `hostname` (string): User's hostname
  - `reason` (string, optional): Quit reason

**Example:**

```json
{
    "id": "1737000000-0012",
    "type": "user_quit",
    "server": "freenode",
    "nick": "bob",
    "text": "Ping timeout",
    "timestamp": 1737000011,
    "extra": {
        "hostname": "bob!~bob@example.com",
        "reason": "Ping timeout"
    }
}
```

---

#### 4.3 Away Status Changed

**Message Type:** `away`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"away"`
- `server` (string): Server tag
- `text` (string, optional): Away message (empty if unaway)
- `timestamp` (integer): Unix timestamp

**Example (Set Away):**

```json
{
    "id": "1737000000-0013",
    "type": "away",
    "server": "freenode",
    "text": "Gone for lunch",
    "timestamp": 1737000012
}
```

**Example (Unaway):**

```json
{
    "id": "1737000000-0014",
    "type": "away",
    "server": "freenode",
    "text": "",
    "timestamp": 1737000013
}
```

---

### 5. Nicklist

#### 5.1 Full Nicklist

Sent when client requests NAMES or joins a channel.

**Message Type:** `nicklist`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"nicklist"`
- `server` (string): Server tag
- `channel` (string): Channel name
- `text` (string): JSON array of users
- `timestamp` (integer): Unix timestamp

**User Object Fields:**
- `nick` (string): Nickname
- `prefix` (string): Mode prefix (`@` for op, `+` for voice, etc.)

**Example:**

```json
{
    "id": "1737000000-0015",
    "type": "nicklist",
    "server": "freenode",
    "channel": "#channel",
    "text": "[{\"nick\":\"alice\",\"prefix\":\"@\"},{\"nick\":\"bob\",\"prefix\":\"+\"},{\"nick\":\"charlie\",\"prefix\":\"\"}]",
    "timestamp": 1737000014
}
```

**Parsing nicklist:**

```javascript
const users = JSON.parse(message.text);
// users = [
//   { nick: 'alice', prefix: '@' },
//   { nick: 'bob', prefix: '+' },
//   { nick: 'charlie', prefix: '' }
// ]
```

---

#### 5.2 Nicklist Update

Sent when a single user is added, removed, or their mode changes.

**Message Type:** `nicklist_update`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"nicklist_update"`
- `server` (string): Server tag
- `channel` (string): Channel name
- `nick` (string): Affected nickname
- `text` (string): Update type (see below)
- `timestamp` (integer): Unix timestamp

**Update Types:**
- `"add"`: User joined channel
- `"remove"`: User left channel
- `"+o"`: User gained op
- `"-o"`: User lost op
- `"+v"`: User gained voice
- `"-v"`: User lost voice
- `"+h"`: User gained halfop
- `"-h"`: User lost halfop

**Example (User Gained Op):**

```json
{
    "id": "1737000000-0016",
    "type": "nicklist_update",
    "server": "freenode",
    "channel": "#channel",
    "nick": "alice",
    "text": "+o",
    "timestamp": 1737000015
}
```

---

### 6. Server Information

#### 6.1 Server Status

Sent when server connects, disconnects, or client subscribes.

**Message Type:** `server_status`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"server_status"`
- `server` (string): Server tag
- `text` (string): Status (`"connected"` or `"disconnected"`)
- `nick` (string, optional): Current nickname (if connected)
- `timestamp` (integer): Unix timestamp

**Example (Connected):**

```json
{
    "id": "1737000000-0017",
    "type": "server_status",
    "server": "freenode",
    "text": "connected",
    "nick": "mynick",
    "timestamp": 1737000016
}
```

**Example (Disconnected):**

```json
{
    "id": "1737000000-0018",
    "type": "server_status",
    "server": "freenode",
    "text": "disconnected",
    "timestamp": 1737000017
}
```

---

#### 6.2 WHOIS Response

Complete WHOIS information for a user.

**Message Type:** `whois`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"whois"`
- `server` (string): Server tag
- `nick` (string): Queried nickname
- `timestamp` (integer): Unix timestamp
- `extra` (object): WHOIS data
  - `user` (string): Username
  - `host` (string): Hostname
  - `realname` (string): Real name
  - `server` (string, optional): Connected server
  - `server_info` (string, optional): Server description
  - `channels` (string, optional): Space-separated channel list
  - `idle` (string, optional): Idle time
  - `signon` (string, optional): Signon time
  - `account` (string, optional): Account name (IRCv3)
  - `secure` (boolean, optional): Using secure connection
  - `oper` (boolean, optional): Is IRC operator
  - `special` (array, optional): Other WHOIS lines

**Example:**

```json
{
    "id": "1737000000-0019",
    "type": "whois",
    "server": "freenode",
    "nick": "alice",
    "timestamp": 1737000018,
    "extra": {
        "user": "alice",
        "host": "example.com",
        "realname": "Alice Smith",
        "server": "irc.freenode.net",
        "server_info": "Freenode Server",
        "channels": "#channel #another",
        "idle": "120",
        "signon": "1737000000",
        "account": "alice_account",
        "secure": true,
        "oper": false
    }
}
```

---

### 7. Activity Tracking

#### 7.1 Activity Update

Sent when activity level changes for a window (channel or query).

**Message Type:** `activity_update`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"activity_update"`
- `server` (string): Server tag
- `channel` (string): Channel or nick name
- `level` (integer): Activity level (0-3)
- `timestamp` (integer): Unix timestamp

**Activity Levels:**
- `0`: No activity (read)
- `1`: Normal message
- `2`: Highlight (mention)
- `3`: Other activity (joins, parts, etc.)

**Example:**

```json
{
    "id": "1737000000-0020",
    "type": "activity_update",
    "server": "freenode",
    "channel": "#channel",
    "level": 2,
    "timestamp": 1737000019
}
```

---

### 8. Query Windows

#### 8.1 Query Opened

Sent when a private message window is created.

**Message Type:** `query_opened`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"query_opened"`
- `server` (string): Server tag
- `nick` (string): Query target nickname
- `timestamp` (integer): Unix timestamp

**Example:**

```json
{
    "id": "1737000000-0021",
    "type": "query_opened",
    "server": "freenode",
    "nick": "alice",
    "timestamp": 1737000020
}
```

---

#### 8.2 Query Closed

Sent when a private message window is closed.

**Message Type:** `query_closed`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"query_closed"`
- `server` (string): Server tag
- `nick` (string): Query target nickname
- `timestamp` (integer): Unix timestamp

**Example:**

```json
{
    "id": "1737000000-0022",
    "type": "query_closed",
    "server": "freenode",
    "nick": "alice",
    "timestamp": 1737000021
}
```

---

### 9. Network and Server Management

#### 9.1 Network List Response

**Message Type:** `network_list_response`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"network_list_response"`
- `text` (string): JSON array of networks
- `timestamp` (integer): Unix timestamp

**Network Object Fields:**
- `name` (string): Network name
- `chat_type` (string): Protocol type (e.g., "IRC")
- `nick` (string, optional): Default nickname
- `username` (string, optional): Username/ident
- `realname` (string, optional): Real name
- `autosendcmd` (string, optional): Auto-send commands

**Example:**

```json
{
    "id": "1737000000-0023",
    "type": "network_list_response",
    "text": "[{\"name\":\"freenode\",\"chat_type\":\"IRC\",\"nick\":\"mynick\",\"username\":\"myuser\",\"realname\":\"My Name\"}]",
    "timestamp": 1737000022
}
```

---

#### 9.2 Server List Response

**Message Type:** `server_list_response`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"server_list_response"`
- `text` (string): JSON array of servers
- `timestamp` (integer): Unix timestamp

**Server Object Fields:**
- `name` (string): Server identifier
- `host` (string): Hostname or IP
- `port` (integer): Port number
- `chatnet` (string, optional): Associated network
- `use_tls` (boolean): SSL/TLS enabled
- `autoconnect` (boolean): Auto-connect on startup

**Example:**

```json
{
    "id": "1737000000-0024",
    "type": "server_list_response",
    "text": "[{\"name\":\"irc.freenode.net\",\"host\":\"irc.freenode.net\",\"port\":6697,\"chatnet\":\"freenode\",\"use_tls\":true,\"autoconnect\":true}]",
    "timestamp": 1737000023
}
```

---

#### 9.3 Command Result

Response to network/server add/remove operations.

**Message Type:** `command_result`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"command_result"`
- `text` (string): JSON result object
- `timestamp` (integer): Unix timestamp

**Result Object Fields:**
- `success` (boolean): Operation succeeded
- `message` (string): Human-readable message
- `error_code` (integer, optional): Error code if failed

**Example (Success):**

```json
{
    "id": "1737000000-0025",
    "type": "command_result",
    "text": "{\"success\":true,\"message\":\"Network added successfully\"}",
    "timestamp": 1737000024
}
```

**Example (Failure):**

```json
{
    "id": "1737000000-0026",
    "type": "command_result",
    "text": "{\"success\":false,\"message\":\"Network already exists\",\"error_code\":1}",
    "timestamp": 1737000025
}
```

---

### 10. Control Messages

#### 10.1 Pong

Response to ping message.

**Message Type:** `pong`

**Fields:**
- `type` (string): `"pong"`
- `timestamp` (integer): Unix timestamp

**Example:**

```json
{
    "type": "pong",
    "timestamp": 1737000026
}
```

---

#### 10.2 Error

Error message from server.

**Message Type:** `error`

**Fields:**
- `id` (string): Message ID
- `type` (string): `"error"`
- `text` (string): Error description
- `timestamp` (integer): Unix timestamp

**Example:**

```json
{
    "id": "1737000000-0027",
    "type": "error",
    "text": "Failed to send message: not connected",
    "timestamp": 1737000027
}
```

---

## Message Type Reference

### Complete Type List

| Type | Direction | Description |
|------|-----------|-------------|
| `auth_ok` | S→C | Authentication successful |
| `message` | S→C | Public/private message |
| `channel_join` | S→C | User joined channel |
| `channel_part` | S→C | User left channel |
| `channel_kick` | S→C | User kicked from channel |
| `channel_mode` | S→C | Channel mode changed |
| `topic` | S→C | Topic changed |
| `nick_change` | S→C | User changed nickname |
| `user_quit` | S→C | User quit IRC |
| `away` | S→C | Away status changed |
| `nicklist` | S→C | Full channel user list |
| `nicklist_update` | S→C | Single user add/remove/mode |
| `server_status` | S→C | Server connected/disconnected |
| `whois` | S→C | WHOIS response |
| `activity_update` | S→C | Activity level changed |
| `query_opened` | S→C | Query window opened |
| `query_closed` | S→C | Query window closed |
| `network_list_response` | S→C | Network list |
| `server_list_response` | S→C | Server list |
| `command_result` | S→C | Operation result |
| `pong` | S→C | Ping response |
| `error` | S→C | Error message |
| `sync_server` | C→S | Subscribe to server |
| `command` | C→S | Execute IRC command |
| `ping` | C→S | Keep-alive |
| `close_query` | C→S | Close query window |
| `names` | C→S | Request channel user list |
| `mark_read` | C→S | Clear activity markers |
| `network_list` | C→S | Request network list |
| `network_add` | C→S | Add/modify network |
| `network_remove` | C→S | Remove network |
| `server_list` | C→S | Request server list |
| `server_add` | C→S | Add/modify server |
| `server_remove` | C→S | Remove server |

*Direction: S→C = Server to Client, C→S = Client to Server*

---

## Data Structures

### Message Levels

IRC message levels are bitflags indicating message type and importance.

```javascript
const MSGLEVEL_CRAP       = 0x01;   // Unimportant messages
const MSGLEVEL_MSGS       = 0x02;   // Private messages
const MSGLEVEL_PUBLIC     = 0x04;   // Public messages
const MSGLEVEL_NOTICES    = 0x08;   // Notices
const MSGLEVEL_SNOTES     = 0x10;   // Server notices
const MSGLEVEL_CTCPS      = 0x20;   // CTCPs
const MSGLEVEL_ACTIONS    = 0x80;   // ACTION messages (/me)
const MSGLEVEL_JOINS      = 0x100;  // Joins
const MSGLEVEL_PARTS      = 0x200;  // Parts
const MSGLEVEL_QUITS      = 0x400;  // Quits
const MSGLEVEL_KICKS      = 0x800;  // Kicks
const MSGLEVEL_MODES      = 0x1000; // Mode changes
const MSGLEVEL_TOPICS     = 0x2000; // Topic changes
const MSGLEVEL_WALLOPS    = 0x4000; // Wallops
const MSGLEVEL_NICKS      = 0x8000; // Nick changes
const MSGLEVEL_DCC        = 0x10000; // DCC events
const MSGLEVEL_CLIENTERROR = 0x20000; // Client errors
const MSGLEVEL_CLIENTNOTICE = 0x40000; // Client notices
const MSGLEVEL_HILIGHT    = 0x80000; // Highlights
```

**Usage:**

```javascript
// Check if message is an ACTION
const isAction = (message.level & MSGLEVEL_ACTIONS) !== 0;

// Check if message is a highlight
const isHighlight = (message.level & MSGLEVEL_HILIGHT) !== 0;

// Check if public message
const isPublic = (message.level & MSGLEVEL_PUBLIC) !== 0;

// Check if private message
const isPrivate = (message.level & MSGLEVEL_MSGS) !== 0;
```

---

## Error Handling

### Connection Errors

**1. Authentication Failed**
- **Cause**: Wrong password
- **Behavior**: Connection closes immediately after handshake
- **Solution**: Verify password matches `fe_web_password` setting

**2. SSL/TLS Error**
- **Cause**: Certificate verification failed
- **Behavior**: WebSocket connection fails
- **Solution**: Accept self-signed certificate or use proper certificates

**3. Connection Refused**
- **Cause**: Server not listening
- **Behavior**: WebSocket connection fails
- **Solution**: Ensure `fe_web_enabled ON` and correct port

### Message Errors

**1. Decryption Failed**
- **Cause**: Wrong key or corrupted data
- **Behavior**: Cannot parse message
- **Solution**: Verify key derivation matches server

**2. Invalid JSON**
- **Cause**: Malformed message
- **Behavior**: JSON parsing fails
- **Solution**: Check message format and encoding

**3. Unknown Message Type**
- **Cause**: Unsupported or new message type
- **Behavior**: Client doesn't know how to handle
- **Solution**: Log and ignore, or update client

---

## Examples

### Complete Client Implementation

```javascript
class IrssiWebClient {
    constructor(url, password) {
        this.url = url;
        this.password = password;
        this.ws = null;
        this.key = null;
    }

    async connect() {
        // Derive encryption key
        this.key = await this.deriveKey(this.password);

        // Connect WebSocket
        const encodedPassword = encodeURIComponent(this.password);
        this.ws = new WebSocket(`${this.url}/?password=${encodedPassword}`);

        this.ws.onopen = () => this.onOpen();
        this.ws.onmessage = (e) => this.onMessage(e);
        this.ws.onerror = (e) => this.onError(e);
        this.ws.onclose = () => this.onClose();
    }

    async deriveKey(password) {
        const encoder = new TextEncoder();
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits']
        );

        const salt = encoder.encode('irssi-fe-web-v1');
        const keyMaterial = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 10000,
                hash: 'SHA-256'
            },
            passwordKey,
            256
        );

        return await crypto.subtle.importKey(
            'raw',
            keyMaterial,
            'AES-GCM',
            false,
            ['encrypt', 'decrypt']
        );
    }

    async decrypt(encryptedData) {
        const data = new Uint8Array(encryptedData);
        const iv = data.slice(0, 12);
        const ciphertext = data.slice(12, -16);
        const tag = data.slice(-16);

        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            this.key,
            new Uint8Array([...ciphertext, ...tag])
        );

        return new TextDecoder().decode(decrypted);
    }

    async encrypt(json) {
        const encoder = new TextEncoder();
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            this.key,
            encoder.encode(json)
        );

        const result = new Uint8Array(12 + encrypted.byteLength);
        result.set(iv, 0);
        result.set(new Uint8Array(encrypted), 12);

        return result;
    }

    onOpen() {
        console.log('Connected to irssi-fe-web');

        // Subscribe to all servers
        this.send({ type: 'sync_server', server: '*' });

        // Start ping interval
        this.pingInterval = setInterval(() => {
            this.send({ type: 'ping' });
        }, 30000);
    }

    async onMessage(event) {
        if (event.data instanceof Blob) {
            const buffer = await event.data.arrayBuffer();
            const json = await this.decrypt(buffer);
            const message = JSON.parse(json);
            this.handleMessage(message);
        }
    }

    handleMessage(message) {
        console.log('Received:', message);

        switch (message.type) {
            case 'auth_ok':
                console.log('Authenticated');
                break;

            case 'message':
                this.handleChatMessage(message);
                break;

            case 'channel_join':
                console.log(`${message.nick} joined ${message.channel}`);
                break;

            case 'channel_part':
                console.log(`${message.nick} left ${message.channel}`);
                break;

            case 'nick_change':
                console.log(`${message.nick} is now ${message.text}`);
                break;

            case 'nicklist':
                const users = JSON.parse(message.text);
                console.log(`${message.channel} users:`, users);
                break;

            case 'activity_update':
                console.log(`Activity in ${message.channel}: level ${message.level}`);
                break;

            case 'pong':
                console.log('Pong received');
                break;

            default:
                console.log('Unknown message type:', message.type);
        }
    }

    handleChatMessage(message) {
        const MSGLEVEL_ACTIONS = 128;
        const isAction = (message.level & MSGLEVEL_ACTIONS) !== 0;

        if (message.is_highlight) {
            console.log(`[HIGHLIGHT] ${message.channel} <${message.nick}> ${message.text}`);
        } else if (isAction) {
            console.log(`${message.channel} * ${message.nick} ${message.text}`);
        } else {
            console.log(`${message.channel} <${message.nick}> ${message.text}`);
        }
    }

    async send(data) {
        const json = JSON.stringify(data);
        const encrypted = await this.encrypt(json);
        this.ws.send(encrypted);
    }

    sendMessage(server, channel, text) {
        this.send({
            type: 'command',
            server: server,
            command: `PRIVMSG ${channel} :${text}`
        });
    }

    joinChannel(server, channel) {
        this.send({
            type: 'command',
            server: server,
            command: `JOIN ${channel}`
        });
    }

    markAsRead(server, channel) {
        this.send({
            type: 'mark_read',
            server: server,
            channel: channel
        });
    }

    onError(error) {
        console.error('WebSocket error:', error);
    }

    onClose() {
        console.log('Disconnected from irssi-fe-web');
        clearInterval(this.pingInterval);
    }

    disconnect() {
        if (this.ws) {
            this.ws.close();
        }
    }
}

// Usage
const client = new IrssiWebClient('wss://localhost:9001', 'your_password');
await client.connect();

// Send a message
client.sendMessage('freenode', '#channel', 'Hello, world!');

// Join a channel
client.joinChannel('freenode', '#new-channel');

// Mark channel as read
client.markAsRead('freenode', '#channel');
```

---

## Conclusion

This API provides comprehensive access to irssi IRC functionality through a secure WebSocket interface. All messages are strongly encrypted and authenticated, ensuring privacy and security for your IRC communications.

For implementation questions or issues, please refer to the main [README.md](../README.md) or open an issue on GitHub.
