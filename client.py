import json
import os
import shlex
import socket
import sys
from typing import Dict, Optional, Tuple

# -------------------------------------------------------------
# Mini-Splunk CLI Client
# -------------------------------------------------------------
# What this client does:
# - Reads commands from the user.
# - Connects to the server using TCP.
# - Sends one JSON request.
# - Prints the server response in a readable way.
#
# Network reminder:
# - Use 127.0.0.1:65432 when client and server are on the same machine.
# - Use the server machine's real IP address when they are on different machines.
# -------------------------------------------------------------

HEADER_SIZE = 16
DEFAULT_HOSTPORT = "127.0.0.1:65432"
DEFAULT_PAGE_SIZE = 20

LAST_QUERY: Optional[Dict] = None

HELP_TEXT = f"""
Mini-Splunk CLI Commands
========================

1. HELP
   Shows this help menu.

2. INGEST <file_path> <host:port>
   Upload a local syslog file to the server so the server can parse and index it.
   Example:
     INGEST SVR1_server_auth_syslog.txt {DEFAULT_HOSTPORT}

3. QUERY <host:port> <query_type> <value> [PAGE <number>] [SIZE <number>]
   Search the indexed logs.

   Supported query types:
     SEARCH_DATE
     SEARCH_HOST
     SEARCH_DAEMON
     SEARCH_SEVERITY
     SEARCH_KEYWORD
     COUNT_KEYWORD

   Examples:
     QUERY {DEFAULT_HOSTPORT} SEARCH_DATE "Feb 22"
     QUERY {DEFAULT_HOSTPORT} SEARCH_HOST SYSSVR1
     QUERY {DEFAULT_HOSTPORT} SEARCH_DAEMON sshd
     QUERY {DEFAULT_HOSTPORT} SEARCH_KEYWORD "Failed password" PAGE 2
     QUERY {DEFAULT_HOSTPORT} SEARCH_KEYWORD "Failed password" PAGE 3 SIZE 10

4. NEXT
   Show the next page of the most recent pageable QUERY.

5. PREV
   Show the previous page of the most recent pageable QUERY.

6. PAGE <number>
   Jump to a specific page of the most recent pageable QUERY.
   Example:
     PAGE 4

7. PURGE <host:port>
   Delete every indexed log entry from the server database.
   Example:
     PURGE {DEFAULT_HOSTPORT}

8. STATS <host:port>
   Show total indexed logs and the top hosts, processes, and severities.
   Example:
     STATS {DEFAULT_HOSTPORT}

9. EXIT or QUIT
   Leave the client.

10. Ctrl+C
    Exits the client or cancels the current operation gracefully.
""".strip()


def recv_exact(sock: socket.socket, size: int) -> Optional[bytes]:
    """Receive exactly 'size' bytes from the socket."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_json(sock: socket.socket) -> Optional[Dict]:
    """Receive one length-prefixed JSON response from the server."""
    header = recv_exact(sock, HEADER_SIZE)
    if not header:
        return None

    try:
        length = int(header.decode())
    except ValueError as exc:
        raise ValueError("Invalid response header received from server.") from exc

    payload = recv_exact(sock, length)
    if not payload:
        return None

    return json.loads(payload.decode())


def send_json(sock: socket.socket, obj: Dict) -> None:
    """Send one length-prefixed JSON request to the server."""
    payload = json.dumps(obj).encode()
    header = f"{len(payload):0{HEADER_SIZE}d}".encode()
    sock.sendall(header + payload)


def parse_hostport(text: str) -> Tuple[str, int]:
    """Split a value like 127.0.0.1:65432 into ('127.0.0.1', 65432)."""
    host, port_text = text.rsplit(":", 1)
    return host, int(port_text)


def talk(host: str, port: int, payload: Dict) -> Optional[Dict]:
    """Open one connection, send one request, receive one response."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        send_json(sock, payload)
        return recv_json(sock)


def remember_query(host: str, port: int, query_type: str, value: str, page: int, page_size: int, response: Dict) -> None:
    """Save the last pageable query so NEXT/PREV/PAGE can reuse it."""
    global LAST_QUERY

    if query_type == "COUNT_KEYWORD":
        return

    LAST_QUERY = {
        "host": host,
        "port": port,
        "query_type": query_type,
        "value": value,
        "page": response.get("page", page),
        "page_size": response.get("page_size", page_size),
        "total_pages": response.get("total_pages", 0),
    }


def print_response(response: Optional[Dict]) -> None:
    """Show the server response in a user-friendly format."""
    if not response:
        print("[System Message] No response from server.")
        return

    print(f"[Server Response] {response.get('status', 'UNKNOWN')}")

    if "message" in response:
        print(response["message"])

    query_type = response.get("query_type")
    query_value = response.get("query_value")

    if query_type == "COUNT_KEYWORD":
        count = response.get("count", 0)
        print(f"The keyword '{query_value}' appears in {count:,} indexed log entr{'y' if count == 1 else 'ies' }.")
        return

    if query_type and "count" in response:
        total = response.get("count", 0)
        returned = response.get("returned", len(response.get("results", [])))
        print(f"Found {total:,} matching entr{'y' if total == 1 else 'ies' }.")

        if "page" in response:
            page = response.get("page", 1)
            total_pages = response.get("total_pages", 0)
            start_index = response.get("start_index", 0)
            end_index = response.get("end_index", 0)

            if total_pages == 0:
                print("No pages available because there are no matching results.")
            else:
                print(f"Page {page} of {total_pages}")
                if returned:
                    print(f"Showing results {start_index:,} to {end_index:,}.")

    start_number = response.get("start_index", 1)
    for offset, line in enumerate(response.get("results", [])):
        print(f"{start_number + offset}. {line}")

    if "total_logs" in response:
        print(f"Total logs: {response['total_logs']:,}")

        print("Top hosts:")
        for row in response.get("top_hosts", []):
            print(f"  - {row['hostname']}: {row['count']:,}")

        print("Top processes:")
        for row in response.get("top_processes", []):
            print(f"  - {row['process']}: {row['count']:,}")

        print("Top severity:")
        for row in response.get("top_severity", []):
            print(f"  - {row['severity']}: {row['count']:,}")


def issue_query(host: str, port: int, query_type: str, value: str, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE, remember: bool = True) -> bool:
    print("[System Message] Sending query...")
    response = talk(
        host,
        port,
        {
            "action": "QUERY",
            "query_type": query_type,
            "value": value,
            "page": page,
            "page_size": page_size,
        },
    )
    print_response(response)

    if remember and response and response.get("status") == "SUCCESS":
        remember_query(host, port, query_type, value, page, page_size, response)
    return True


def parse_query_tail(tokens) -> Tuple[str, int, int]:
    """
    Parse the part after QUERY <host:port> <query_type>.

    Supports optional PAGE <n> and SIZE <n> anywhere in the remaining tokens.
    Everything else is treated as part of the query value.
    """
    value_tokens = []
    page = 1
    page_size = DEFAULT_PAGE_SIZE

    index = 0
    while index < len(tokens):
        upper_token = tokens[index].upper()
        if upper_token == "PAGE" and index + 1 < len(tokens):
            page = int(tokens[index + 1])
            index += 2
            continue
        if upper_token == "SIZE" and index + 1 < len(tokens):
            page_size = int(tokens[index + 1])
            index += 2
            continue
        value_tokens.append(tokens[index])
        index += 1

    value = " ".join(value_tokens).strip()
    return value, page, page_size


def handle_paging_shortcut(command: str, parts) -> bool:
    global LAST_QUERY

    if LAST_QUERY is None:
        print("[System Message] No previous pageable query is available yet.")
        return True

    current_page = LAST_QUERY["page"]
    total_pages = LAST_QUERY.get("total_pages", 0)

    if command == "NEXT":
        if total_pages == 0 or current_page >= total_pages:
            print("[System Message] You are already on the last available page.")
            return True
        target_page = current_page + 1
    elif command == "PREV":
        if current_page <= 1:
            print("[System Message] You are already on the first page.")
            return True
        target_page = current_page - 1
    else:  # PAGE <number>
        if len(parts) != 2:
            print("Usage: PAGE <number>")
            return True
        target_page = int(parts[1])
        if target_page < 1:
            print("[System Message] Page number must be at least 1.")
            return True

    return issue_query(
        LAST_QUERY["host"],
        LAST_QUERY["port"],
        LAST_QUERY["query_type"],
        LAST_QUERY["value"],
        page=target_page,
        page_size=LAST_QUERY["page_size"],
        remember=True,
    )


def handle_command(line: str) -> bool:
    """
    Parse one command typed by the user.

    Returns False only when the user wants to exit.
    Returns True otherwise.
    """
    parts = shlex.split(line)
    if not parts:
        return True

    command = parts[0].upper()

    if command == "HELP":
        print(HELP_TEXT)
        return True

    if command in ("EXIT", "QUIT"):
        return False

    if command in ("NEXT", "PREV", "PAGE"):
        return handle_paging_shortcut(command, parts)

    if command == "INGEST":
        if len(parts) != 3:
            print("Usage: INGEST <file_path> <host:port>")
            return True

        file_path, hostport = parts[1], parts[2]
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return True

        host, port = parse_hostport(hostport)

        with open(file_path, "r", encoding="utf-8", errors="replace") as file_obj:
            content = file_obj.read()

        print(f"[System Message] Connecting to {host}:{port}...")
        print(f"[System Message] Uploading syslog ({len(content):,} bytes)...")

        response = talk(
            host,
            port,
            {
                "action": "INGEST",
                "filename": os.path.basename(file_path),
                "content": content,
            },
        )
        print_response(response)
        return True

    if command == "QUERY":
        if len(parts) < 4:
            print("Usage: QUERY <host:port> <query_type> <value> [PAGE <number>] [SIZE <number>]")
            return True

        host, port = parse_hostport(parts[1])
        query_type = parts[2].upper()
        value, page, page_size = parse_query_tail(parts[3:])

        if not value:
            print("[System Message] Query value cannot be empty.")
            return True

        return issue_query(host, port, query_type, value, page=page, page_size=page_size, remember=True)

    if command == "PURGE":
        if len(parts) != 2:
            print("Usage: PURGE <host:port>")
            return True

        host, port = parse_hostport(parts[1])
        print(f"[System Message] Connecting to {host}:{port} to purge records...")
        response = talk(host, port, {"action": "PURGE"})
        print_response(response)
        return True

    if command == "STATS":
        if len(parts) != 2:
            print("Usage: STATS <host:port>")
            return True

        host, port = parse_hostport(parts[1])
        print("[System Message] Requesting statistics...")
        response = talk(host, port, {"action": "STATS"})
        print_response(response)
        return True

    print("Unknown command.")
    print("Type HELP to see all available commands.")
    return True


def main() -> None:
    """Start the client in one-shot mode or interactive mode."""
    if len(sys.argv) > 1:
        line = " ".join(sys.argv[1:])
        try:
            handle_command(line)
        except KeyboardInterrupt:
            print("\n[System Message] Operation cancelled by user.")
        except Exception as exc:
            print(f"[System Message] Error: {exc}")
        return

    print("Mini-Splunk CLI")
    print("Type HELP to see commands.")
    print("Type EXIT to quit.")

    while True:
        try:
            line = input("client> ")
        except KeyboardInterrupt:
            print("\n[System Message] Ctrl+C received. Exiting client gracefully.")
            break
        except EOFError:
            break

        try:
            if not handle_command(line):
                break
        except KeyboardInterrupt:
            print("\n[System Message] Operation cancelled by user.")
        except Exception as exc:
            print(f"[System Message] Error: {exc}")


if __name__ == "__main__":
    main()
