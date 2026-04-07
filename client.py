import json
import os
import shlex
import socket
import sys
from typing import Dict, Optional, Tuple

# ============================================================
# Mini-Splunk CLI Client
# ============================================================
# What this client does:
# - Reads commands from the user.
# - Connects to the server using TCP.
# - Sends one JSON request.
# - Prints the server response in a readable way.
#
# Network reminder:
# - Use 127.0.0.1:65432 when client and server are on the same machine.
# - Use the server machine's real IP address when they are on different machines.
# ============================================================

HEADER_SIZE = 16
DEFAULT_HOSTPORT = "127.0.0.1:65432"

HELP_TEXT = f"""
Mini-Splunk CLI Commands
========================

1. HELP
   Shows this help menu.

2. INGEST <file_path> <host:port>
   Upload a local syslog file to the server so the server can parse and index it.
   Example:
     INGEST SVR1_server_auth_syslog.txt {DEFAULT_HOSTPORT}

3. QUERY <host:port> SEARCH_DATE \"<date text>\"
   Search logs by timestamp prefix.
   Example:
     QUERY {DEFAULT_HOSTPORT} SEARCH_DATE \"Feb 22\"

4. QUERY <host:port> SEARCH_HOST <hostname>
   Search logs by hostname.
   Example:
     QUERY {DEFAULT_HOSTPORT} SEARCH_HOST SYSSVR1

5. QUERY <host:port> SEARCH_DAEMON <daemon_name>
   Search logs by process / daemon name.
   Example:
     QUERY {DEFAULT_HOSTPORT} SEARCH_DAEMON sshd

6. QUERY <host:port> SEARCH_SEVERITY <severity>
   Search logs by severity label.
   Example:
     QUERY {DEFAULT_HOSTPORT} SEARCH_SEVERITY ERROR

7. QUERY <host:port> SEARCH_KEYWORD \"<word or phrase>\"
   Search messages containing a word or phrase.
   Example:
     QUERY {DEFAULT_HOSTPORT} SEARCH_KEYWORD \"Failed password\"

8. QUERY <host:port> COUNT_KEYWORD \"<word or phrase>\"
   Count how many indexed logs contain the word or phrase.
   Example:
     QUERY {DEFAULT_HOSTPORT} COUNT_KEYWORD Deactivated

9. PURGE <host:port>
   Delete every indexed log entry from the server database.
   Example:
     PURGE {DEFAULT_HOSTPORT}

10. STATS <host:port>
    Show total indexed logs and the top hosts, processes, and severities.
    Example:
      STATS {DEFAULT_HOSTPORT}

11. EXIT or QUIT
    Leave the client.

12. Ctrl+C
    Cancels the current client session gracefully.
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
        print(f"The keyword '{query_value}' appears in {count} indexed log entr{'y' if count == 1 else 'ies'}.")
        return

    if query_type and "count" in response:
        total = response.get("count", 0)
        returned = response.get("returned", len(response.get("results", [])))
        print(f"Found {total} matching entr{'y' if total == 1 else 'ies' }.")
        if total > returned:
            print(f"Showing first {returned} result(s):")

    for index, line in enumerate(response.get("results", []), start=1):
        print(f"{index}. {line}")

    if "total_logs" in response:
        print(f"Total logs: {response['total_logs']}")

        print("Top hosts:")
        for row in response.get("top_hosts", []):
            print(f"  - {row['hostname']}: {row['count']}")

        print("Top processes:")
        for row in response.get("top_processes", []):
            print(f"  - {row['process']}: {row['count']}")

        print("Top severity:")
        for row in response.get("top_severity", []):
            print(f"  - {row['severity']}: {row['count']}")


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

    try:
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
                print("Usage: QUERY <host:port> <query_type> <value>")
                return True

            host, port = parse_hostport(parts[1])
            query_type = parts[2].upper()
            value = " ".join(parts[3:])

            print("[System Message] Sending query...")
            response = talk(
                host,
                port,
                {
                    "action": "QUERY",
                    "query_type": query_type,
                    "value": value,
                },
            )
            print_response(response)
            return True

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

        print("Unknown command. Type HELP to see the available commands.")
        return True

    except KeyboardInterrupt:
        print("\n[System Message] Operation cancelled by user.")
        return True
    except FileNotFoundError as exc:
        print(f"[System Message] File error: {exc}")
        return True
    except ConnectionRefusedError:
        print("[System Message] Connection refused. Make sure the server is running and the IP/port is correct.")
        return True
    except socket.timeout:
        print("[System Message] Network timeout while talking to the server.")
        return True
    except OSError as exc:
        print(f"[System Message] Network error: {exc}")
        return True
    except ValueError as exc:
        print(f"[System Message] Input error: {exc}")
        return True


def main() -> None:
    """
    Start the interactive client.

    Graceful Ctrl+C behavior:
    - in interactive mode: exit the client cleanly
    - during a running command: cancel that command and return to the prompt
    """
    if len(sys.argv) > 1:
        line = " ".join(sys.argv[1:])
        try:
            handle_command(line)
        except KeyboardInterrupt:
            print("\n[System Message] Client stopped by user.")
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
            print()
            break

        if not handle_command(line):
            break


if __name__ == "__main__":
    main()
