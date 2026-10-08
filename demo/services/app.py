"""Clavure demo e-commerce application (synthetic data only).

One stdlib-only program, role selected with CLAVURE_ROLE:

  storefront       HTTP :8080  POST /checkout  -> order-service
  order-service    HTTP :8080  POST /orders    -> orders-db, payment-service
  payment-service  HTTP :8080  POST /charge    -> finance-db
  reporting        HTTP :8080  GET  /report    -> orders-db
  orders-db        TCP  :5432  line protocol;  HTTP :9187 metrics
  finance-db       TCP  :5432  line protocol;  HTTP :9187 metrics

The "databases" are in-memory emulators speaking a tiny line protocol
(PING, INSERT, FIND, COUNT, SUMMARY). All records are synthetic.

Sub-commands used by Clavure's trusted controller inside pods:

  serve     run the role
  probe     one TCP connection attempt; prints a JSON result
  http      one HTTP request to a URL; prints a JSON result
  dbquery   one line-protocol command against a local database port
  idle      do nothing (restricted adversarial probe pods)
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("CLAVURE_ROLE", "storefront")
ORDER_SERVICE = os.environ.get(
    "ORDER_SERVICE_URL", "http://order-service.clavure-shop.svc.cluster.local"
)
PAYMENT_SERVICE = os.environ.get(
    "PAYMENT_SERVICE_URL", "http://payment-service.clavure-shop.svc.cluster.local"
)
ORDERS_DB = os.environ.get("ORDERS_DB_HOST", "orders-db.clavure-data.svc.cluster.local")
FINANCE_DB = os.environ.get("FINANCE_DB_HOST", "finance-db.clavure-data.svc.cluster.local")
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "4"))


def log(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} [{ROLE}] {msg}", flush=True)


# --------------------------------------------------------------------------
# Database emulator
# --------------------------------------------------------------------------

SEED = {
    "orders-db": {
        "orders": [
            {
                "id": "seed-1",
                "item": "synthetic-widget",
                "amount": 19.99,
                "correlation_id": "seed-1",
            },
            {
                "id": "seed-2",
                "item": "synthetic-gadget",
                "amount": 5.00,
                "correlation_id": "seed-2",
            },
        ]
    },
    "finance-db": {
        "ledger": [
            {"id": "inv-1001", "amount": 19.99, "correlation_id": "seed-1", "status": "settled"}
        ],
        "payroll": [{"id": "emp-0001", "name": "Synthetic Employee", "salary": 1}],
    },
}


class Database:
    def __init__(self, role: str):
        self.tables = {k: list(v) for k, v in SEED.get(role, {}).items()}
        self.lock = threading.Lock()

    def handle(self, line: str) -> str:
        parts = line.strip().split(" ", 2)
        cmd = parts[0].upper() if parts else ""
        with self.lock:
            if cmd == "PING":
                return f"PONG {ROLE}"
            if cmd == "INSERT" and len(parts) == 3:
                rec = json.loads(parts[2])
                rec.setdefault("id", uuid.uuid4().hex[:12])
                self.tables.setdefault(parts[1], []).append(rec)
                return f"OK {rec['id']}"
            if cmd == "FIND" and len(parts) == 3:
                hits = [
                    r for r in self.tables.get(parts[1], []) if r.get("correlation_id") == parts[2]
                ]
                return json.dumps(hits)
            if cmd == "COUNT" and len(parts) >= 2:
                return str(len(self.tables.get(parts[1], [])))
            if cmd == "SUMMARY" and len(parts) >= 2:
                rows = self.tables.get(parts[1], [])
                return json.dumps(
                    {"rows": len(rows), "total": round(sum(r.get("amount", 0) for r in rows), 2)}
                )
        return "ERR unknown command"


def serve_db() -> None:
    db = Database(ROLE)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 5432))
    srv.listen(64)

    def client(conn: socket.socket, addr) -> None:
        with conn:
            conn.settimeout(10)
            f = conn.makefile("rwb")
            try:
                for raw in f:
                    reply = db.handle(raw.decode(errors="replace"))
                    f.write((reply + "\n").encode())
                    f.flush()
            except (OSError, ValueError) as exc:
                log(f"client {addr} error: {exc}")

    def metrics() -> None:
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = f'db_up{{role="{ROLE}"}} 1\n'.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        ThreadingHTTPServer(("0.0.0.0", 9187), H).serve_forever()

    threading.Thread(target=metrics, daemon=True).start()
    log("database emulator listening on :5432 (metrics :9187)")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=client, args=(conn, addr), daemon=True).start()


def db_call(host: str, command: str, port: int = 5432, timeout: float = UPSTREAM_TIMEOUT) -> str:
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall((command + "\n").encode())
        return s.makefile("rb").readline().decode().strip()


# --------------------------------------------------------------------------
# HTTP services
# --------------------------------------------------------------------------


def http_json(
    url: str, method: str = "GET", payload: dict | None = None, timeout: float = UPSTREAM_TIMEOUT
):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode() or "{}")


class Handler(BaseHTTPRequestHandler):
    server_version = "clavure-demo"

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n).decode() or "{}") if n else {}

    def log_message(self, fmt, *args):
        log(fmt % args)

    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "role": ROLE})
        if ROLE == "reporting" and self.path == "/report":
            try:
                summary = json.loads(db_call(ORDERS_DB, "SUMMARY orders"))
            except (OSError, ValueError) as exc:
                return self._send(502, {"ok": False, "error": f"orders-db unreachable: {exc}"})
            return self._send(
                200, {"ok": True, "orders": summary["rows"], "revenue": summary["total"]}
            )
        return self._send(404, {"ok": False})

    def do_POST(self):
        try:
            body = self._body()
        except ValueError:
            return self._send(400, {"ok": False, "error": "invalid json"})
        cid = str(body.get("correlation_id") or uuid.uuid4().hex)
        try:
            if ROLE == "storefront" and self.path == "/checkout":
                order = {
                    "item": body.get("item", "synthetic-item"),
                    "amount": float(body.get("amount", 9.99)),
                    "correlation_id": cid,
                }
                status, resp = http_json(f"{ORDER_SERVICE}/orders", "POST", order)
                return self._send(status, {"ok": resp.get("ok", False), "checkout": resp})
            if ROLE == "order-service" and self.path == "/orders":
                order_id = db_call(ORDERS_DB, "INSERT orders " + json.dumps(body))
                status, pay = http_json(
                    f"{PAYMENT_SERVICE}/charge",
                    "POST",
                    {"amount": body.get("amount"), "correlation_id": cid},
                )
                return self._send(
                    200 if status == 200 else 502,
                    {"ok": status == 200, "order": order_id, "payment": pay},
                )
            if ROLE == "payment-service" and self.path == "/charge":
                entry = db_call(
                    FINANCE_DB,
                    "INSERT ledger "
                    + json.dumps(
                        {"amount": body.get("amount"), "correlation_id": cid, "status": "captured"}
                    ),
                )
                return self._send(200, {"ok": entry.startswith("OK"), "ledger": entry})
        except (OSError, urllib.error.URLError, ValueError) as exc:
            return self._send(502, {"ok": False, "error": f"upstream failure: {exc}"})
        return self._send(404, {"ok": False})


def serve_http() -> None:
    log("http service listening on :8080")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


# --------------------------------------------------------------------------
# Probe / client commands (run by Clavure inside pods)
# --------------------------------------------------------------------------


def probe(host: str, port: int, timeout: float, send: str | None) -> dict:
    out: dict = {
        "target": host,
        "port": port,
        "resolved": None,
        "status": "ERROR",
        "response": None,
    }
    t0 = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        out["resolved"] = infos[0][4][0]
    except socket.gaierror as exc:
        out.update(status="DNS_ERROR", error=str(exc))
        return out
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((out["resolved"], port))
        out["status"] = "CONNECTED"
        if send:
            try:
                s.sendall((send + "\n").encode())
                out["response"] = s.makefile("rb").readline().decode(errors="replace").strip()[:200]
            except OSError as exc:
                out["response_error"] = str(exc)
    except TimeoutError:
        out["status"] = "TIMEOUT"
    except ConnectionRefusedError:
        out["status"] = "REFUSED"
    except ConnectionResetError:
        out["status"] = "RESET"
    except OSError as exc:
        out["status"] = (
            "UNREACHABLE" if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH) else "ERROR"
        )
        out["error"] = str(exc)
    finally:
        s.close()
        out["elapsed_ms"] = round((time.monotonic() - t0) * 1000, 1)
    return out


def cmd_http(url: str, method: str, data: str | None, timeout: float) -> dict:
    try:
        payload = json.loads(data) if data else None
        status, body = http_json(url, method, payload, timeout)
        return {"status": status, "body": body}
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode() or "{}")
        except ValueError:
            body = {}
        return {"status": exc.code, "body": body}
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return {"status": None, "error": str(exc)}


def main() -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    sub.add_parser("idle")
    pr = sub.add_parser("probe")
    pr.add_argument("--host", required=True)
    pr.add_argument("--port", type=int, required=True)
    pr.add_argument("--timeout", type=float, default=3.0)
    pr.add_argument("--send")
    h = sub.add_parser("http")
    h.add_argument("--url", required=True)
    h.add_argument("--method", default="GET")
    h.add_argument("--data")
    h.add_argument("--timeout", type=float, default=10.0)
    q = sub.add_parser("dbquery")
    q.add_argument("--port", type=int, default=5432)
    q.add_argument("--cmd", required=True)
    args = p.parse_args()

    # As PID 1 the default SIGTERM action is ignored by the kernel; exit promptly.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    if args.command == "serve":
        if ROLE in ("orders-db", "finance-db"):
            serve_db()
        else:
            serve_http()
    elif args.command == "idle":
        while True:
            time.sleep(3600)
    elif args.command == "probe":
        print(json.dumps(probe(args.host, args.port, args.timeout, args.send)))
    elif args.command == "http":
        print(json.dumps(cmd_http(args.url, args.method, args.data, args.timeout)))
    elif args.command == "dbquery":
        print(db_call("127.0.0.1", args.cmd, port=args.port, timeout=5))
    return 0


if __name__ == "__main__":
    sys.exit(main())
