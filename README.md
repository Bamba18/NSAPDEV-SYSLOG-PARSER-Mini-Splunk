# Concurrent Syslog Analytics Server ("Mini-Splunk")

A lightweight client-server log management system built with Python sockets, threads, regular expressions, and SQLite. The server accepts syslog files from multiple clients, parses them into structured fields, stores them centrally, and answers search, count, statistics, and purge requests.

---

## Features

- Concurrent TCP server using Python threads
- Centralized log storage using SQLite
- Supports **RFC 5424** and classic **RFC 3164-style** syslog lines
- Search by:
  - date
  - host
  - daemon/process
  - severity
  - keyword
- Count keyword matches without printing all results
- Pagination support:
  - `PAGE <n>`
  - `NEXT`
  - `PREV`
  - custom page size via `SIZE <n>`
- Graceful `Ctrl+C` shutdown for both server and client
- Works locally or across VMs / Proxmox if the server IP and port are reachable

---

## System Architecture

```text
+-------------------+          TCP / JSON + length header          +--------------------------+
|   CLI Client      |  ---------------------------------------->   |   Syslog Server          |
|   (client.py)     |                                             |   (server.py)           |
|                   |  <----------------------------------------   |                          |
+-------------------+               JSON response                  +--------------------------+
                                                                           |
                                                                           v
                                                                +--------------------------+
                                                                | SQLite Database          |
                                                                | syslog_index.db          |
                                                                +--------------------------+
```

### High-level flow

1. The client reads a command from the user.
2. The client opens a TCP connection to the server.
3. The client sends a JSON request prefixed by a fixed-length header.
4. The server receives the request.
5. If the request is `INGEST`, the server parses the uploaded syslog file and stores structured records in SQLite.
6. If the request is `QUERY`, `COUNT`, `PURGE`, or `STATS`, the server performs the database operation and returns a JSON response.
7. The client prints the response in a readable format.

---

## Supported Syslog Formats

### RFC 5424 example

```text
<34>1 2024-02-22T10:00:00Z host app 1234 ID47 Message text
```

### Classic syslog / RFC 3164-style example

```text
Feb 22 00:00:09 ccs-cuda sshd[133388]: Failed password for root from 1.2.3.4 port 12345 ssh2
```

### Parsed fields

Each valid log line is stored with these fields:

- `timestamp`
- `hostname`
- `process`
- `severity`
- `message`
- `raw_line`

---

## Project Files

```text
.
├── client.py
├── server.py
├── self_test.py
├── README.txt
└── syslog_index.db          # created automatically when the server runs
```

---

## Requirements

- Python **3.10+** recommended
- No external Python packages required
- Uses only Python standard library modules plus SQLite through `sqlite3`

---

## How to Run

Open **two terminals** in the same folder.

### 1. Start the server

```bash
python server.py
```

Expected output:

```text
Server listening on 0.0.0.0:65432
```

### 2. Start the client

```bash
python client.py
```

Expected output:

```text
Mini-Splunk CLI
Type HELP to see commands.
Type EXIT to quit.
```

### 3. Show the help menu

```text
HELP
```

---

## Client Commands

| Command | Purpose | Example |
|---|---|---|
| `HELP` | Show command guide | `HELP` |
| `INGEST <file_path> <host:port>` | Upload and index a syslog file | `INGEST CUDA_server_auth_syslog.txt 127.0.0.1:65432` |
| `QUERY <host:port> SEARCH_DATE "<date>" [PAGE n] [SIZE n]` | Search by date prefix | `QUERY 127.0.0.1:65432 SEARCH_DATE "Feb 22"` |
| `QUERY <host:port> SEARCH_HOST <host> [PAGE n] [SIZE n]` | Search by hostname | `QUERY 127.0.0.1:65432 SEARCH_HOST ccs-cuda` |
| `QUERY <host:port> SEARCH_DAEMON <daemon> [PAGE n] [SIZE n]` | Search by process/daemon | `QUERY 127.0.0.1:65432 SEARCH_DAEMON sshd` |
| `QUERY <host:port> SEARCH_SEVERITY <level> [PAGE n] [SIZE n]` | Search by severity | `QUERY 127.0.0.1:65432 SEARCH_SEVERITY ERROR` |
| `QUERY <host:port> SEARCH_KEYWORD "<text>" [PAGE n] [SIZE n]` | Search messages by keyword/phrase | `QUERY 127.0.0.1:65432 SEARCH_KEYWORD "Failed password" PAGE 2` |
| `QUERY <host:port> COUNT_KEYWORD "<text>"` | Count keyword matches only | `QUERY 127.0.0.1:65432 COUNT_KEYWORD "Failed password"` |
| `NEXT` | Show next page of the most recent pageable query | `NEXT` |
| `PREV` | Show previous page of the most recent pageable query | `PREV` |
| `PAGE <n>` | Jump to a specific page of the most recent pageable query | `PAGE 4` |
| `PURGE <host:port>` | Delete all indexed log entries | `PURGE 127.0.0.1:65432` |
| `STATS <host:port>` | Show totals and top categories | `STATS 127.0.0.1:65432` |
| `EXIT` / `QUIT` | Leave the client | `EXIT` |

---

## Search Behavior

- `SEARCH_HOST` is case-insensitive
- `SEARCH_DAEMON` is case-insensitive
- `SEARCH_SEVERITY` is case-insensitive
- `SEARCH_KEYWORD` and `COUNT_KEYWORD` are case-insensitive substring searches
- Query results are paged
- Default page size is **20**
- Maximum page size is capped in the server to prevent extreme requests

### Example queries

```text
QUERY 127.0.0.1:65432 SEARCH_DATE "Feb 22"
QUERY 127.0.0.1:65432 SEARCH_HOST SYSSVR1
QUERY 127.0.0.1:65432 SEARCH_DAEMON sshd
QUERY 127.0.0.1:65432 SEARCH_SEVERITY ERROR
QUERY 127.0.0.1:65432 SEARCH_KEYWORD "Failed password"
QUERY 127.0.0.1:65432 SEARCH_KEYWORD "Failed password" PAGE 2
QUERY 127.0.0.1:65432 SEARCH_KEYWORD "Failed password" PAGE 3 SIZE 10
QUERY 127.0.0.1:65432 COUNT_KEYWORD Deactivated
```

---

## Pagination

The client prints one page of results at a time.

### Default behavior

- Default page = `1`
- Default page size = `20`

### Example

```text
QUERY 127.0.0.1:65432 SEARCH_KEYWORD "Failed password" PAGE 2 SIZE 10
```

This means:
- search for the phrase `Failed password`
- show page `2`
- print `10` results per page

### Browse the same query again

After a pageable query, you can continue browsing the same result set with:

```text
NEXT
PREV
PAGE 5
```

---

## Graceful Shutdown

### Server

Press `Ctrl+C` in the server terminal.

Expected output:

```text
[System Message] Ctrl+C received. Shutting down server gracefully...
[System Message] Server stopped.
```

### Client

Press `Ctrl+C` in the client terminal.

Expected output:

```text
[System Message] Ctrl+C received. Exiting client gracefully.
```

---

## Running in a VM or Proxmox

This project can run:

- on one local machine
- inside a VM
- across multiple VMs
- on Proxmox guests

### If client and server are on the same machine or same VM

Use:

```text
127.0.0.1:65432
```

### If server is in another VM or another machine

Use the **server machine's real IP address**, for example:

```text
192.168.1.50:65432
```

### Important note

Do **not** use `127.0.0.1` from a different machine, because that points back to the client machine itself.

---

## Testing

### Quick manual test

1. Start the server
2. Start the client
3. Run:

```text
PURGE 127.0.0.1:65432
INGEST CUDA_server_auth_syslog.txt 127.0.0.1:65432
QUERY 127.0.0.1:65432 SEARCH_HOST ccs-cuda
QUERY 127.0.0.1:65432 SEARCH_DAEMON sshd
QUERY 127.0.0.1:65432 SEARCH_KEYWORD "Failed password"
STATS 127.0.0.1:65432
```

### Automated tests

```bash
python self_test.py --quick
python self_test.py --cuda
python self_test.py --full
```

---

## Implementation Notes

- The server uses **TCP sockets** for communication.
- Each accepted client connection is handled in a **separate thread**.
- SQLite is used as the **central shared data store**.
- A lock protects database operations to keep concurrent access simple and safe.
- The client-server protocol uses **JSON messages with a fixed-size length header** instead of fragile delimiter splitting.

---

## References

1. R. Gerhards, *The Syslog Protocol*, RFC 5424, Mar. 2009.
2. C. Lonvick, *The BSD Syslog Protocol*, RFC 3164, Aug. 2001.
3. Python Software Foundation, *The Python Standard Library*, Python Documentation.
4. Python Software Foundation, *socket — Low-level networking interface*, Python Documentation.
5. Python Software Foundation, *threading — Thread-based parallelism*, Python Documentation.
6. Python Software Foundation, *sqlite3 — DB-API 2.0 interface for SQLite databases*, Python Documentation.
7. SQLite Documentation, *Write-Ahead Logging*.

---

## Authors

- Team Member: `Ivan Antonio Alvarez`
- Course: `NSAPDEV`
- Term/AY: `2nd Term AY 2025–2026`
