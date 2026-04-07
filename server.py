import json
import os
import re
import socket
import sqlite3
import threading
from typing import Dict, List, Optional, Tuple

# ==============================
# Mini-Splunk Syslog Server
# ==============================
# This server accepts TCP client connections, receives syslog files,
# parses each line, stores parsed records in SQLite, and answers
# search/count/purge commands.
#
# Design choices:
# - Native Python sockets + threads to satisfy the project requirement.
# - SQLite as the centralized shared store.
# - A single re-entrant lock keeps database operations safe and simple.
# - Parsing happens OUTSIDE the lock so multiple clients can still upload
#   and parse in parallel before writing their batches to the database.
#
# The code is intentionally kept straightforward and heavily commented
# so it is easier to study.

HOST = "0.0.0.0"
PORT = 65432
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "syslog_index.db")
INSERT_BATCH_SIZE = 5000     # insert rows in chunks to avoid memory spikes
PREVIEW_LIMIT = 20           # how many matching rows to show to the client
HEADER_SIZE = 16             # fixed-size length prefix for each JSON message
ACCEPT_TIMEOUT = 1.0         # lets Ctrl+C break the accept loop cleanly

# Regex for RFC 5424 syslog lines.
# Example:
# <34>1 2024-02-22T10:00:00Z host app 1234 ID47 message
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<rest>.*)$"
)

# Regex for classic RFC 3164-style syslog lines.
# Example:
# Feb 22 00:00:09 ccs-cuda sshd[133388]: Failed password for root ...
#
# Notes:
# - Single-digit days in classic syslog may have 2 spaces, e.g. "Feb  7".
# - The process part is captured lazily up to the first colon.
RFC3164_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^:]+?)\s*:\s*"
    r"(?P<message>.*)$"
)

# Syslog severity number -> readable label.
SEVERITY_MAP = {
    0: "EMERG",
    1: "ALERT",
    2: "CRIT",
    3: "ERROR",
    4: "WARN",
    5: "NOTICE",
    6: "INFO",
    7: "DEBUG",
}


def normalize_spaces(text: str) -> str:
    """Collapse repeated whitespace into a single space."""
    return " ".join(text.split())


def infer_severity(message: str) -> str:
    """
    Infer a severity when the log line does not contain an explicit
    RFC 5424 severity value.

    This is useful for classic auth/syslog lines like the uploaded samples.
    """
    text = message.upper()

    # Stronger / more critical keywords first.
    if "EMERG" in text:
        return "EMERG"
    if "ALERT" in text:
        return "ALERT"
    if "CRIT" in text or "CRITICAL" in text:
        return "CRIT"

    # Treat failures and explicit errors as ERROR.
    if "ERROR" in text or "FAILED" in text or "FAILURE" in text:
        return "ERROR"

    # Warnings and invalid attempts.
    if "WARN" in text or "WARNING" in text or "INVALID" in text:
        return "WARN"

    if "DEBUG" in text:
        return "DEBUG"
    if "NOTICE" in text:
        return "NOTICE"

    return "INFO"


class LogStore:
    """Small wrapper around SQLite so the rest of the code stays clean."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.lock = threading.RLock()
        self._init_db()

    def _connect(self):
        """
        Open a fresh SQLite connection.
        check_same_thread=False is needed because multiple server threads
        will access the database.
        """
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    hostname TEXT NOT NULL,
                    process TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    raw_line TEXT NOT NULL
                )
                """
            )

            # Helpful indexes so searches are faster on large files.
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_hostname ON logs(hostname)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_process ON logs(process)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)")
            conn.commit()

    def insert_many(self, rows: List[Tuple[str, str, str, str, str, str]]) -> None:
        """Insert a batch of parsed rows safely."""
        with self.lock:
            with self._connect() as conn:
                conn.executemany(
                    """
                    INSERT INTO logs (timestamp, hostname, process, severity, message, raw_line)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                conn.commit()

    def query_many(self, sql: str, params: Tuple = ()) -> List[Dict]:
        """Run a SELECT that returns many rows."""
        with self.lock:
            with self._connect() as conn:
                cur = conn.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]

    def query_one(self, sql: str, params: Tuple = ()) -> Optional[Dict]:
        """Run a SELECT that returns a single row."""
        with self.lock:
            with self._connect() as conn:
                cur = conn.execute(sql, params)
                row = cur.fetchone()
                return dict(row) if row else None

    def purge(self) -> int:
        """
        Delete all indexed logs.
        The same lock is used here so PURGE behaves like an exclusive write.
        """
        with self.lock:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) AS total FROM logs").fetchone()[0]
                conn.execute("DELETE FROM logs")
                conn.commit()
                return total


store = LogStore(DB_PATH)


def parse_syslog_line(line: str):
    """
    Parse one syslog line.

    Returns a tuple matching the database columns:
    (timestamp, hostname, process, severity, message, raw_line)

    Returns None if the line cannot be parsed.
    """
    line = line.rstrip("\r\n")
    if not line:
        return None

    # Try RFC 5424 first.
    match = RFC5424_RE.match(line)
    if match:
        pri = int(match.group("pri"))
        severity = SEVERITY_MAP.get(pri % 8, "INFO")

        appname = match.group("appname")
        procid = match.group("procid")
        process = appname if procid == "-" else f"{appname}[{procid}]"

        return (
            normalize_spaces(match.group("timestamp")),
            match.group("hostname"),
            process,
            severity,
            match.group("rest"),
            line,
        )

    # Then try RFC 3164 / classic syslog.
    match = RFC3164_RE.match(line)
    if match:
        message = match.group("message")
        return (
            normalize_spaces(match.group("timestamp")),
            match.group("hostname"),
            match.group("process").strip(),
            infer_severity(message),
            message,
            line,
        )

    return None


def recv_exact(sock: socket.socket, size: int):
    """Receive exactly size bytes from a socket, or None if it closes."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_json(sock: socket.socket):
    """
    Read one length-prefixed JSON message.
    Message format:
    - first HEADER_SIZE bytes = payload length written as digits
    - then the JSON payload bytes
    """
    header = recv_exact(sock, HEADER_SIZE)
    if not header:
        return None

    try:
        length = int(header.decode())
    except ValueError as exc:
        raise ValueError("Invalid message header received.") from exc

    payload = recv_exact(sock, length)
    if not payload:
        return None

    return json.loads(payload.decode())


def send_json(sock: socket.socket, obj: Dict) -> None:
    """Send one length-prefixed JSON message."""
    payload = json.dumps(obj).encode()
    header = f"{len(payload):0{HEADER_SIZE}d}".encode()
    sock.sendall(header + payload)


def handle_ingest(request: Dict) -> Dict:
    """
    Parse and index one uploaded syslog file.

    Parsing is done before each database write batch so we do not hold the
    database lock longer than needed.
    """
    text = request.get("content", "")
    parsed_rows: List[Tuple[str, str, str, str, str, str]] = []
    parsed_count = 0
    invalid_count = 0

    for line in text.splitlines():
        if not line.strip():
            continue

        row = parse_syslog_line(line)
        if row is None:
            invalid_count += 1
            continue

        parsed_rows.append(row)
        parsed_count += 1

        if len(parsed_rows) >= INSERT_BATCH_SIZE:
            store.insert_many(parsed_rows)
            parsed_rows.clear()

    if parsed_rows:
        store.insert_many(parsed_rows)

    return {
        "status": "SUCCESS",
        "message": f"File received and {parsed_count:,} syslog entries parsed and indexed.",
        "parsed_count": parsed_count,
        "invalid_count": invalid_count,
        "filename": request.get("filename", ""),
    }


def build_response_for_search(query_type: str, query_value: str, count_sql: str, preview_sql: str, params: Tuple) -> Dict:
    """Run a count query plus a preview query, then build one consistent response."""
    count_row = store.query_one(count_sql, params)
    total_count = count_row["total"] if count_row else 0
    preview_rows = store.query_many(preview_sql, params)

    return {
        "status": "SUCCESS",
        "query_type": query_type,
        "query_value": query_value,
        "count": total_count,
        "returned": len(preview_rows),
        "results": [row["raw_line"] for row in preview_rows],
    }


def handle_query(request: Dict) -> Dict:
    """Handle all search/count query types from the client."""
    query_type = request.get("query_type", "").upper()
    value = request.get("value", "")

    if query_type == "SEARCH_DATE":
        normalized_value = normalize_spaces(value)
        params = (f"{normalized_value}%",)
        return build_response_for_search(
            "SEARCH_DATE",
            value,
            "SELECT COUNT(*) AS total FROM logs WHERE timestamp LIKE ?",
            f"SELECT raw_line FROM logs WHERE timestamp LIKE ? ORDER BY id LIMIT {PREVIEW_LIMIT}",
            params,
        )

    if query_type == "SEARCH_HOST":
        params = (value,)
        return build_response_for_search(
            "SEARCH_HOST",
            value,
            "SELECT COUNT(*) AS total FROM logs WHERE LOWER(hostname) = LOWER(?)",
            f"SELECT raw_line FROM logs WHERE LOWER(hostname) = LOWER(?) ORDER BY id LIMIT {PREVIEW_LIMIT}",
            params,
        )

    if query_type == "SEARCH_DAEMON":
        params = (f"{value}%",)
        return build_response_for_search(
            "SEARCH_DAEMON",
            value,
            "SELECT COUNT(*) AS total FROM logs WHERE LOWER(process) LIKE LOWER(?)",
            f"SELECT raw_line FROM logs WHERE LOWER(process) LIKE LOWER(?) ORDER BY id LIMIT {PREVIEW_LIMIT}",
            params,
        )

    if query_type == "SEARCH_SEVERITY":
        params = (value,)
        return build_response_for_search(
            "SEARCH_SEVERITY",
            value,
            "SELECT COUNT(*) AS total FROM logs WHERE UPPER(severity) = UPPER(?)",
            f"SELECT raw_line FROM logs WHERE UPPER(severity) = UPPER(?) ORDER BY id LIMIT {PREVIEW_LIMIT}",
            params,
        )

    if query_type == "SEARCH_KEYWORD":
        params = (f"%{value}%",)
        return build_response_for_search(
            "SEARCH_KEYWORD",
            value,
            "SELECT COUNT(*) AS total FROM logs WHERE message LIKE ?",
            f"SELECT raw_line FROM logs WHERE message LIKE ? ORDER BY id LIMIT {PREVIEW_LIMIT}",
            params,
        )

    if query_type == "COUNT_KEYWORD":
        row = store.query_one("SELECT COUNT(*) AS total FROM logs WHERE message LIKE ?", (f"%{value}%",))
        total_count = row["total"] if row else 0
        return {
            "status": "SUCCESS",
            "query_type": "COUNT_KEYWORD",
            "query_value": value,
            "count": total_count,
            "returned": 0,
            "results": [],
        }

    return {
        "status": "ERROR",
        "message": f"Unknown query type: {query_type}",
    }


def handle_purge(_: Dict) -> Dict:
    """Erase all currently indexed logs."""
    total = store.purge()
    return {
        "status": "SUCCESS",
        "message": f"{total:,} indexed log entries have been erased.",
        "purged": total,
    }


def handle_stats(_: Dict) -> Dict:
    """Return simple top-level statistics about the indexed logs."""
    total_logs = store.query_one("SELECT COUNT(*) AS total FROM logs")["total"]
    top_hosts = store.query_many(
        "SELECT hostname, COUNT(*) AS count FROM logs GROUP BY hostname ORDER BY count DESC LIMIT 10"
    )
    top_processes = store.query_many(
        "SELECT process, COUNT(*) AS count FROM logs GROUP BY process ORDER BY count DESC LIMIT 10"
    )
    top_severity = store.query_many(
        "SELECT severity, COUNT(*) AS count FROM logs GROUP BY severity ORDER BY count DESC LIMIT 10"
    )

    return {
        "status": "SUCCESS",
        "total_logs": total_logs,
        "top_hosts": top_hosts,
        "top_processes": top_processes,
        "top_severity": top_severity,
    }


def client_thread(conn: socket.socket, addr: Tuple[str, int]) -> None:
    """
    Handle exactly one client request on one thread.

    Flow:
    - receive request
    - check action
    - run matching handler
    - send response
    - close connection
    """
    try:
        request = recv_json(conn)
        if request is None:
            return

        action = request.get("action", "").upper()

        if action == "INGEST":
            response = handle_ingest(request)
        elif action == "QUERY":
            response = handle_query(request)
        elif action == "PURGE":
            response = handle_purge(request)
        elif action == "STATS":
            response = handle_stats(request)
        else:
            response = {
                "status": "ERROR",
                "message": f"Unknown action: {action}",
            }

        send_json(conn, response)

    except Exception as exc:
        try:
            send_json(conn, {"status": "ERROR", "message": str(exc)})
        except Exception:
            pass
    finally:
        conn.close()


def main() -> None:
    """
    Start the TCP server and keep accepting clients until Ctrl+C is pressed.

    Graceful Ctrl+C behavior:
    - stop accepting new clients
    - close the listening socket cleanly
    - let already-finished requests exit normally
    - print a clear shutdown message instead of a scary traceback
    """
    worker_threads: List[threading.Thread] = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen()
        server_sock.settimeout(ACCEPT_TIMEOUT)

        print(f"Server listening on {HOST}:{PORT}")
        print(f"Database file: {DB_PATH}")
        print("Press Ctrl+C to stop the server gracefully.")

        try:
            while True:
                try:
                    conn, addr = server_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    # Happens if the listening socket closes during shutdown.
                    break

                thread = threading.Thread(target=client_thread, args=(conn, addr), daemon=True)
                thread.start()
                worker_threads.append(thread)

        except KeyboardInterrupt:
            print("\n[System Message] Ctrl+C received. Shutting down server gracefully...")

        finally:
            try:
                server_sock.close()
            except OSError:
                pass

            # Give worker threads a short chance to finish any in-progress request.
            for thread in worker_threads:
                thread.join(timeout=0.2)

            print("[System Message] Server stopped.")


if __name__ == "__main__":
    main()
