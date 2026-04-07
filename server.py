import json
import math
import os
import re
import socket
import sqlite3
import threading
from typing import Dict, List, Optional, Tuple

# ============================================================
# Mini-Splunk Syslog Server
# ============================================================
# This server accepts TCP client connections, receives syslog files,
# parses them, stores them in SQLite, and answers search/count/purge
# requests.
#
# Key design choices:
# - TCP sockets + Python threads for concurrent clients.
# - SQLite as the centralized shared data store.
# - One simple lock around database operations to keep concurrent access
#   safe and easy to understand.
# - JSON messages with a fixed-length header so large uploads do not break.
# ============================================================

HOST = "0.0.0.0"
PORT = 65432
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "syslog_index.db")

HEADER_SIZE = 16          # length prefix size for JSON messages
INSERT_BATCH_SIZE = 5000  # write rows to SQLite in chunks
DEFAULT_PAGE_SIZE = 20    # default number of search results shown per page
MAX_PAGE_SIZE = 100       # cap so one query does not request an extreme page size
ACCEPT_TIMEOUT = 1.0      # helps Ctrl+C stop the server cleanly

# ============================================================
# Regular expressions for supported syslog formats
# ============================================================

# RFC 5424 example:
# <34>1 2024-02-22T10:00:00Z host app 1234 ID47 Message text
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<message>.*)$"
)

# Classic syslog / RFC 3164-style example:
# Feb 22 00:00:09 ccs-cuda sshd[133388]: Failed password for root ...
RFC3164_RE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>[^:]+?)\s*:\s*"
    r"(?P<message>.*)$"
)

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

shutdown_event = threading.Event()
client_threads: List[threading.Thread] = []
client_threads_lock = threading.Lock()


def normalize_spaces(text: str) -> str:
    """Collapse repeated whitespace into a single space."""
    return " ".join(text.split())


def infer_severity(message: str) -> str:
    """
    Infer a readable severity for classic syslog lines that do not include
    an explicit RFC 5424 priority field.
    """
    text = message.upper()

    if "EMERG" in text:
        return "EMERG"
    if "ALERT" in text:
        return "ALERT"
    if "CRIT" in text or "CRITICAL" in text:
        return "CRIT"
    if "ERROR" in text or "FAILED" in text or "FAILURE" in text:
        return "ERROR"
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

    def _connect(self) -> sqlite3.Connection:
        """
        Open a fresh SQLite connection.
        check_same_thread=False is needed because multiple server threads
        use the database.
        """
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
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
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_hostname ON logs(hostname)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_process ON logs(process)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)")
            conn.commit()

    def insert_many(self, rows: List[Tuple[str, str, str, str, str, str]]) -> None:
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
        with self.lock:
            with self._connect() as conn:
                cur = conn.execute(sql, params)
                return [dict(row) for row in cur.fetchall()]

    def query_one(self, sql: str, params: Tuple = ()) -> Optional[Dict]:
        with self.lock:
            with self._connect() as conn:
                cur = conn.execute(sql, params)
                row = cur.fetchone()
                return dict(row) if row else None

    def purge(self) -> int:
        with self.lock:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) AS total FROM logs").fetchone()[0]
                conn.execute("DELETE FROM logs")
                conn.commit()
                return total


store = LogStore(DB_PATH)


def parse_syslog_line(line: str) -> Optional[Tuple[str, str, str, str, str, str]]:
    """
    Parse one syslog line.

    Returns:
        (timestamp, hostname, process, severity, message, raw_line)

    Returns None if the line cannot be parsed.
    """
    line = line.rstrip("\r\n")
    if not line:
        return None

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
            match.group("message"),
            line,
        )

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


# ============================================================
# Socket helpers
# ============================================================

def recv_exact(sock: socket.socket, size: int) -> Optional[bytes]:
    """Receive exactly 'size' bytes from the socket, or None if closed."""
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_json(sock: socket.socket) -> Optional[Dict]:
    """Receive one length-prefixed JSON message."""
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


# ============================================================
# Query helpers
# ============================================================

def sanitize_page(page_value) -> int:
    try:
        page = int(page_value)
    except (TypeError, ValueError):
        page = 1
    return max(1, page)


def sanitize_page_size(page_size_value) -> int:
    try:
        page_size = int(page_size_value)
    except (TypeError, ValueError):
        page_size = DEFAULT_PAGE_SIZE
    return max(1, min(MAX_PAGE_SIZE, page_size))


def count_and_preview(where_sql: str, params: Tuple, page: int, page_size: int) -> Tuple[int, List[str], int, int]:
    """
    Return:
        total_count, preview_lines, current_page, total_pages
    """
    count_row = store.query_one(f"SELECT COUNT(*) AS total FROM logs WHERE {where_sql}", params)
    total_count = count_row["total"] if count_row else 0

    total_pages = math.ceil(total_count / page_size) if total_count else 0

    if total_pages == 0:
        return 0, [], 1, 0

    current_page = min(page, total_pages)
    offset = (current_page - 1) * page_size

    preview_rows = store.query_many(
        f"SELECT raw_line FROM logs WHERE {where_sql} ORDER BY id LIMIT ? OFFSET ?",
        params + (page_size, offset),
    )
    preview_lines = [row["raw_line"] for row in preview_rows]

    return total_count, preview_lines, current_page, total_pages


# ============================================================
# Request handlers
# ============================================================

def handle_ingest(request: Dict) -> Dict:
    """
    Parse and index one uploaded syslog file.

    Parsing is done outside the database lock. SQLite writes happen in
    batches so very large files do not accumulate too much in memory.
    """
    text = request.get("content", "")
    batch: List[Tuple[str, str, str, str, str, str]] = []
    parsed_count = 0
    invalid_count = 0

    for line in text.splitlines():
        if not line.strip():
            continue

        row = parse_syslog_line(line)
        if row is None:
            invalid_count += 1
            continue

        batch.append(row)
        parsed_count += 1

        if len(batch) >= INSERT_BATCH_SIZE:
            store.insert_many(batch)
            batch.clear()

    if batch:
        store.insert_many(batch)

    return {
        "status": "SUCCESS",
        "message": f"File received and {parsed_count:,} syslog entries parsed and indexed.",
        "parsed_count": parsed_count,
        "invalid_count": invalid_count,
    }


def handle_query(request: Dict) -> Dict:
    """Handle all QUERY subcommands required by the project spec."""
    query_type = request.get("query_type", "").upper().strip()
    value = request.get("value", "")
    page = sanitize_page(request.get("page", 1))
    page_size = sanitize_page_size(request.get("page_size", DEFAULT_PAGE_SIZE))

    if query_type == "COUNT_KEYWORD":
        row = store.query_one(
            "SELECT COUNT(*) AS total FROM logs WHERE LOWER(message) LIKE LOWER(?)",
            (f"%{value}%",),
        )
        return {
            "status": "SUCCESS",
            "query_type": query_type,
            "query_value": value,
            "count": row["total"] if row else 0,
            "results": [],
        }

    if query_type == "SEARCH_DATE":
        where_sql = "timestamp LIKE ?"
        params = (f"{normalize_spaces(value)}%",)
    elif query_type == "SEARCH_HOST":
        where_sql = "UPPER(hostname) = UPPER(?)"
        params = (value,)
    elif query_type == "SEARCH_DAEMON":
        # Prefix search lets "sshd" match "sshd[1234]".
        where_sql = "LOWER(process) LIKE LOWER(?)"
        params = (f"{value}%",)
    elif query_type == "SEARCH_SEVERITY":
        where_sql = "UPPER(severity) = UPPER(?)"
        params = (value,)
    elif query_type == "SEARCH_KEYWORD":
        where_sql = "LOWER(message) LIKE LOWER(?)"
        params = (f"%{value}%",)
    else:
        return {"status": "ERROR", "message": f"Unknown query type: {query_type}"}

    total_count, preview_lines, current_page, total_pages = count_and_preview(
        where_sql,
        params,
        page,
        page_size,
    )

    returned = len(preview_lines)
    start_index = ((current_page - 1) * page_size) + 1 if returned else 0
    end_index = start_index + returned - 1 if returned else 0

    return {
        "status": "SUCCESS",
        "query_type": query_type,
        "query_value": value,
        "count": total_count,
        "returned": returned,
        "page": current_page,
        "page_size": page_size,
        "total_pages": total_pages,
        "start_index": start_index,
        "end_index": end_index,
        "results": preview_lines,
    }


def handle_purge(_request: Dict) -> Dict:
    total = store.purge()
    return {
        "status": "SUCCESS",
        "message": f"{total:,} indexed log entries have been erased.",
        "purged": total,
    }


def handle_stats(_request: Dict) -> Dict:
    total = store.query_one("SELECT COUNT(*) AS total FROM logs")["total"]
    by_host = store.query_many(
        "SELECT hostname, COUNT(*) AS count FROM logs GROUP BY hostname ORDER BY count DESC LIMIT 10"
    )
    by_process = store.query_many(
        "SELECT process, COUNT(*) AS count FROM logs GROUP BY process ORDER BY count DESC LIMIT 10"
    )
    by_severity = store.query_many(
        "SELECT severity, COUNT(*) AS count FROM logs GROUP BY severity ORDER BY count DESC LIMIT 10"
    )

    return {
        "status": "SUCCESS",
        "total_logs": total,
        "top_hosts": by_host,
        "top_processes": by_process,
        "top_severity": by_severity,
    }


def process_request(request: Dict) -> Dict:
    action = request.get("action", "").upper().strip()

    if action == "INGEST":
        return handle_ingest(request)
    if action == "QUERY":
        return handle_query(request)
    if action == "PURGE":
        return handle_purge(request)
    if action == "STATS":
        return handle_stats(request)

    return {"status": "ERROR", "message": f"Unknown action: {action}"}


# ============================================================
# Client handling and graceful shutdown
# ============================================================

def client_thread(conn: socket.socket, addr) -> None:
    try:
        request = recv_json(conn)
        if request is None:
            return

        response = process_request(request)
        send_json(conn, response)
    except Exception as exc:
        try:
            send_json(conn, {"status": "ERROR", "message": str(exc)})
        except Exception:
            pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> None:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.settimeout(ACCEPT_TIMEOUT)

    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"Server listening on {HOST}:{PORT}")

        while not shutdown_event.is_set():
            try:
                conn, addr = server_socket.accept()
            except socket.timeout:
                continue

            thread = threading.Thread(target=client_thread, args=(conn, addr), daemon=True)
            with client_threads_lock:
                client_threads.append(thread)
            thread.start()

    except KeyboardInterrupt:
        print("\n[System Message] Ctrl+C received. Shutting down server gracefully...")
        shutdown_event.set()
    finally:
        try:
            server_socket.close()
        except Exception:
            pass

        # Give worker threads a short chance to finish cleanly.
        with client_threads_lock:
            threads_snapshot = list(client_threads)
        for thread in threads_snapshot:
            thread.join(timeout=1.0)

        print("[System Message] Server stopped.")


if __name__ == "__main__":
    main()
