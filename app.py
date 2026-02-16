#!/usr/bin/env python3
import csv
import hashlib
import json
import mimetypes
import os
import secrets
import sqlite3
import time
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from urllib.parse import parse_qs, urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "crm.db")
STATIC_DIR = os.path.join(BASE_DIR, "static")
SESSION_AGE_SECONDS = 60 * 60 * 24 * 7
APP_SALT = os.environ.get("CRM_APP_SALT", "crm-salt-change-me")


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_passcode(passcode: str) -> str:
    value = f"{APP_SALT}:{passcode}".encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def upsert_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO settings(key, value) VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """,
        (key, value),
    )


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = db_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('owner', 'agent')),
            passcode_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sales(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            salesperson_id INTEGER NOT NULL,
            customer_name TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            date_sold TEXT NOT NULL,
            policy_type TEXT,
            carrier TEXT,
            premium_amount REAL NOT NULL,
            agent_commission_rate REAL NOT NULL,
            agency_commission_rate REAL NOT NULL,
            notes TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(salesperson_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS settings(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sales_month ON sales(date_sold);
        CREATE INDEX IF NOT EXISTS idx_sales_owner ON sales(salesperson_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
        """
    )

    now = datetime.utcnow().isoformat(timespec="seconds")
    defaults = [
        ("owner", "Owner", "owner", "owner123!"),
        ("sales1", "Salesman 1", "agent", "agent123!"),
        ("sales2", "Salesman 2", "agent", "agent123!"),
        ("sales3", "Salesman 3", "agent", "agent123!"),
        ("sales4", "Salesman 4", "agent", "agent123!"),
    ]

    for username, display_name, role, passcode in defaults:
        conn.execute(
            """
            INSERT INTO users(username, display_name, role, passcode_hash, created_at)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(username) DO NOTHING
            """,
            (username, display_name, role, hash_passcode(passcode), now),
        )

    upsert_setting(conn, "competition_mode", "1")
    upsert_setting(conn, "default_agent_commission_rate", "10")
    upsert_setting(conn, "default_agency_commission_rate", "18")
    conn.commit()
    conn.close()


class CRMHandler(BaseHTTPRequestHandler):
    server_version = "CRMTool/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path.startswith("/api/"):
            if path == "/api/health":
                return self.send_json(200, {"ok": True})
            if path == "/api/me":
                user = self.require_user()
                if not user:
                    return
                return self.send_json(200, {"user": user})
            if path == "/api/sales":
                user = self.require_user()
                if not user:
                    return
                return self.get_sales(user, query)
            if path == "/api/leaderboard":
                user = self.require_user()
                if not user:
                    return
                return self.get_leaderboard(user, query)
            if path == "/api/metrics":
                user = self.require_user(owner_only=True)
                if not user:
                    return
                return self.get_metrics(query)
            if path == "/api/settings":
                user = self.require_user()
                if not user:
                    return
                return self.get_settings(user)
            if path == "/api/export":
                user = self.require_user(owner_only=True)
                if not user:
                    return
                return self.export_sales(query)
            return self.send_json(404, {"error": "Not found"})

        return self.serve_static(path)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/login":
            return self.post_login()
        if path == "/api/logout":
            return self.post_logout()
        if path == "/api/sales":
            user = self.require_user()
            if not user:
                return
            return self.post_sales(user)
        if path == "/api/upload":
            user = self.require_user(owner_only=True)
            if not user:
                return
            return self.post_upload()
        if path == "/api/settings":
            user = self.require_user(owner_only=True)
            if not user:
                return
            return self.post_settings()

        return self.send_json(404, {"error": "Not found"})

    def log_message(self, fmt, *args):
        return

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def send_json(self, code, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, code, text, content_type="text/plain; charset=utf-8", headers=None):
        body = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def user_from_session(self):
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        jar = cookies.SimpleCookie()
        jar.load(raw_cookie)
        if "session" not in jar:
            return None
        token = jar["session"].value
        now = int(time.time())

        conn = db_conn()
        row = conn.execute(
            """
            SELECT u.id, u.username, u.display_name, u.role
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token = ? AND s.expires_at > ?
            """,
            (token, now),
        ).fetchone()
        conn.close()

        if not row:
            return None
        return dict(row)

    def require_user(self, owner_only=False):
        user = self.user_from_session()
        if not user:
            self.send_json(401, {"error": "Unauthorized"})
            return None
        if owner_only and user["role"] != "owner":
            self.send_json(403, {"error": "Owner only"})
            return None
        return user

    def parse_month(self, query):
        month = query.get("month", [""])[0]
        if not month:
            return datetime.utcnow().strftime("%Y-%m")
        try:
            datetime.strptime(month, "%Y-%m")
            return month
        except ValueError:
            return datetime.utcnow().strftime("%Y-%m")

    def post_login(self):
        data = self.read_json()
        if data is None:
            return self.send_json(400, {"error": "Invalid JSON"})

        username = str(data.get("username", "")).strip()
        passcode = str(data.get("passcode", "")).strip()
        if not username or not passcode:
            return self.send_json(400, {"error": "Username and passcode required"})

        conn = db_conn()
        user = conn.execute(
            "SELECT id, username, display_name, role, passcode_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if not user or user["passcode_hash"] != hash_passcode(passcode):
            conn.close()
            return self.send_json(401, {"error": "Invalid credentials"})

        token = secrets.token_urlsafe(32)
        now = int(time.time())
        expires = now + SESSION_AGE_SECONDS
        conn.execute(
            "INSERT INTO sessions(token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (token, user["id"], expires, now),
        )
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.commit()
        conn.close()

        cookie_header = (
            f"session={token}; Path=/; Max-Age={SESSION_AGE_SECONDS}; "
            "HttpOnly; SameSite=Lax"
        )
        return self.send_json(
            200,
            {
                "ok": True,
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "display_name": user["display_name"],
                    "role": user["role"],
                },
            },
            extra_headers={"Set-Cookie": cookie_header},
        )

    def post_logout(self):
        raw_cookie = self.headers.get("Cookie")
        token = None
        if raw_cookie:
            jar = cookies.SimpleCookie()
            jar.load(raw_cookie)
            if "session" in jar:
                token = jar["session"].value

        if token:
            conn = db_conn()
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()

        return self.send_json(
            200,
            {"ok": True},
            extra_headers={"Set-Cookie": "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"},
        )

    def post_sales(self, user):
        data = self.read_json()
        if data is None:
            return self.send_json(400, {"error": "Invalid JSON"})

        customer_name = str(data.get("customer_name", "")).strip()
        phone = str(data.get("phone", "")).strip()
        address = str(data.get("address", "")).strip()
        date_sold = str(data.get("date_sold", "")).strip()
        policy_type = str(data.get("policy_type", "")).strip()
        carrier = str(data.get("carrier", "")).strip()
        notes = str(data.get("notes", "")).strip()

        if not customer_name:
            return self.send_json(400, {"error": "Customer name is required"})

        try:
            datetime.strptime(date_sold, "%Y-%m-%d")
        except ValueError:
            return self.send_json(400, {"error": "date_sold must be YYYY-MM-DD"})

        try:
            premium = float(data.get("premium_amount", 0))
            if premium <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return self.send_json(400, {"error": "premium_amount must be greater than 0"})

        conn = db_conn()
        default_agent_rate = float(setting(conn, "default_agent_commission_rate", "10"))
        default_agency_rate = float(setting(conn, "default_agency_commission_rate", "18"))

        try:
            agent_rate = float(data.get("agent_commission_rate", default_agent_rate))
            agency_rate = float(data.get("agency_commission_rate", default_agency_rate))
        except (TypeError, ValueError):
            conn.close()
            return self.send_json(400, {"error": "Commission rates must be numeric"})

        if agent_rate < 0 or agency_rate < 0:
            conn.close()
            return self.send_json(400, {"error": "Commission rates cannot be negative"})

        salesperson_id = user["id"]
        if user["role"] == "owner":
            requested_id = data.get("salesperson_id")
            if requested_id is not None:
                check = conn.execute(
                    "SELECT id FROM users WHERE id = ? AND role = 'agent'", (requested_id,)
                ).fetchone()
                if check:
                    salesperson_id = check["id"]

        now = datetime.utcnow().isoformat(timespec="seconds")
        conn.execute(
            """
            INSERT INTO sales(
                salesperson_id, customer_name, phone, address, date_sold,
                policy_type, carrier, premium_amount,
                agent_commission_rate, agency_commission_rate, notes, created_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                salesperson_id,
                customer_name,
                phone,
                address,
                date_sold,
                policy_type,
                carrier,
                premium,
                agent_rate,
                agency_rate,
                notes,
                now,
            ),
        )
        conn.commit()
        conn.close()

        return self.send_json(201, {"ok": True})

    def get_sales(self, user, query):
        month = self.parse_month(query)
        conn = db_conn()
        competition_mode = setting(conn, "competition_mode", "1") == "1"

        where = ["substr(s.date_sold, 1, 7) = ?"]
        params = [month]
        if user["role"] != "owner" and not competition_mode:
            where.append("s.salesperson_id = ?")
            params.append(user["id"])

        rows = conn.execute(
            f"""
            SELECT
                s.id,
                s.date_sold,
                s.customer_name,
                s.phone,
                s.address,
                s.policy_type,
                s.carrier,
                s.premium_amount,
                s.agent_commission_rate,
                s.agency_commission_rate,
                s.notes,
                u.display_name AS salesperson
            FROM sales s
            JOIN users u ON u.id = s.salesperson_id
            WHERE {' AND '.join(where)}
            ORDER BY s.date_sold DESC, s.id DESC
            """,
            params,
        ).fetchall()
        conn.close()

        out = []
        for row in rows:
            out.append(
                {
                    "id": row["id"],
                    "date_sold": row["date_sold"],
                    "customer_name": row["customer_name"],
                    "phone": row["phone"],
                    "address": row["address"],
                    "policy_type": row["policy_type"],
                    "carrier": row["carrier"],
                    "premium_amount": row["premium_amount"],
                    "agent_commission_rate": row["agent_commission_rate"],
                    "agency_commission_rate": row["agency_commission_rate"],
                    "agent_commission_amount": round(
                        row["premium_amount"] * row["agent_commission_rate"] / 100.0, 2
                    ),
                    "agency_commission_amount": round(
                        row["premium_amount"] * row["agency_commission_rate"] / 100.0, 2
                    ),
                    "notes": row["notes"],
                    "salesperson": row["salesperson"],
                }
            )

        return self.send_json(200, {"month": month, "sales": out})

    def get_leaderboard(self, user, query):
        month = self.parse_month(query)
        conn = db_conn()
        competition_mode = setting(conn, "competition_mode", "1") == "1"

        where = ["substr(s.date_sold, 1, 7) = ?"]
        params = [month]
        if user["role"] != "owner" and not competition_mode:
            where.append("u.id = ?")
            params.append(user["id"])

        rows = conn.execute(
            f"""
            SELECT
                u.id,
                u.display_name,
                COUNT(s.id) AS deals,
                COALESCE(SUM(s.premium_amount), 0) AS premium_total,
                COALESCE(SUM(s.premium_amount * s.agent_commission_rate / 100.0), 0) AS agent_commission_total,
                COALESCE(SUM(s.premium_amount * s.agency_commission_rate / 100.0), 0) AS agency_commission_total
            FROM users u
            LEFT JOIN sales s
                ON s.salesperson_id = u.id
                AND substr(s.date_sold, 1, 7) = ?
            WHERE u.role = 'agent'
            """
            + (" AND u.id = ?" if (user["role"] != "owner" and not competition_mode) else "")
            + " GROUP BY u.id, u.display_name ORDER BY premium_total DESC, deals DESC, u.display_name ASC",
            params,
        ).fetchall()
        conn.close()

        data = [
            {
                "id": row["id"],
                "display_name": row["display_name"],
                "deals": int(row["deals"]),
                "premium_total": round(float(row["premium_total"]), 2),
                "agent_commission_total": round(float(row["agent_commission_total"]), 2),
                "agency_commission_total": round(float(row["agency_commission_total"]), 2),
            }
            for row in rows
        ]

        return self.send_json(
            200,
            {
                "month": month,
                "competition_mode": competition_mode,
                "leaderboard": data,
            },
        )

    def get_metrics(self, query):
        month = self.parse_month(query)
        conn = db_conn()

        top = conn.execute(
            """
            SELECT
                COUNT(*) AS deals,
                COALESCE(SUM(premium_amount), 0) AS premium_total,
                COALESCE(SUM(premium_amount * agent_commission_rate / 100.0), 0) AS agent_commission_total,
                COALESCE(SUM(premium_amount * agency_commission_rate / 100.0), 0) AS agency_commission_total
            FROM sales
            WHERE substr(date_sold, 1, 7) = ?
            """,
            (month,),
        ).fetchone()

        by_agent = conn.execute(
            """
            SELECT
                u.display_name,
                COUNT(s.id) AS deals,
                COALESCE(SUM(s.premium_amount), 0) AS premium_total,
                COALESCE(SUM(s.premium_amount * s.agent_commission_rate / 100.0), 0) AS agent_commission_total,
                COALESCE(SUM(s.premium_amount * s.agency_commission_rate / 100.0), 0) AS agency_commission_total
            FROM users u
            LEFT JOIN sales s
                ON s.salesperson_id = u.id
                AND substr(s.date_sold, 1, 7) = ?
            WHERE u.role = 'agent'
            GROUP BY u.id, u.display_name
            ORDER BY premium_total DESC, deals DESC
            """,
            (month,),
        ).fetchall()
        conn.close()

        payload = {
            "month": month,
            "summary": {
                "deals": int(top["deals"]),
                "premium_total": round(float(top["premium_total"]), 2),
                "agent_commission_total": round(float(top["agent_commission_total"]), 2),
                "agency_commission_total": round(float(top["agency_commission_total"]), 2),
            },
            "by_agent": [
                {
                    "display_name": row["display_name"],
                    "deals": int(row["deals"]),
                    "premium_total": round(float(row["premium_total"]), 2),
                    "agent_commission_total": round(float(row["agent_commission_total"]), 2),
                    "agency_commission_total": round(float(row["agency_commission_total"]), 2),
                }
                for row in by_agent
            ],
        }
        return self.send_json(200, payload)

    def get_settings(self, user):
        conn = db_conn()
        competition_mode = setting(conn, "competition_mode", "1")
        data = {"competition_mode": competition_mode == "1"}

        if user["role"] == "owner":
            data["default_agent_commission_rate"] = float(
                setting(conn, "default_agent_commission_rate", "10")
            )
            data["default_agency_commission_rate"] = float(
                setting(conn, "default_agency_commission_rate", "18")
            )
            users = conn.execute(
                "SELECT id, username, display_name FROM users WHERE role = 'agent' ORDER BY id"
            ).fetchall()
            data["agents"] = [dict(row) for row in users]
        conn.close()

        return self.send_json(200, data)

    def post_settings(self):
        data = self.read_json()
        if data is None:
            return self.send_json(400, {"error": "Invalid JSON"})

        conn = db_conn()
        if "competition_mode" in data:
            value = "1" if bool(data.get("competition_mode")) else "0"
            upsert_setting(conn, "competition_mode", value)

        if "default_agent_commission_rate" in data:
            try:
                rate = float(data["default_agent_commission_rate"])
                if rate < 0:
                    raise ValueError
            except (TypeError, ValueError):
                conn.close()
                return self.send_json(400, {"error": "default_agent_commission_rate must be >= 0"})
            upsert_setting(conn, "default_agent_commission_rate", f"{rate}")

        if "default_agency_commission_rate" in data:
            try:
                rate = float(data["default_agency_commission_rate"])
                if rate < 0:
                    raise ValueError
            except (TypeError, ValueError):
                conn.close()
                return self.send_json(400, {"error": "default_agency_commission_rate must be >= 0"})
            upsert_setting(conn, "default_agency_commission_rate", f"{rate}")

        if "agents" in data:
            agents = data.get("agents")
            if not isinstance(agents, list):
                conn.close()
                return self.send_json(400, {"error": "agents must be a list"})

            for item in agents:
                if not isinstance(item, dict):
                    conn.close()
                    return self.send_json(400, {"error": "Each agent payload must be an object"})
                try:
                    agent_id = int(item.get("id"))
                except (TypeError, ValueError):
                    conn.close()
                    return self.send_json(400, {"error": "Agent id must be numeric"})

                display_name = str(item.get("display_name", "")).strip()
                if not display_name:
                    conn.close()
                    return self.send_json(400, {"error": "Agent display_name is required"})

                exists = conn.execute(
                    "SELECT id FROM users WHERE id = ? AND role = 'agent'", (agent_id,)
                ).fetchone()
                if not exists:
                    conn.close()
                    return self.send_json(400, {"error": f"Invalid agent id: {agent_id}"})

                conn.execute(
                    "UPDATE users SET display_name = ? WHERE id = ?",
                    (display_name, agent_id),
                )

        conn.commit()
        conn.close()
        return self.send_json(200, {"ok": True})

    def normalize_col(self, name: str) -> str:
        return (
            name.lower()
            .replace("#", "")
            .replace("(", "")
            .replace(")", "")
            .replace("-", " ")
            .replace("_", " ")
            .strip()
        )

    def parse_csv_value(self, row, aliases):
        for alias in aliases:
            value = row.get(alias)
            if value is not None and str(value).strip() != "":
                return str(value).strip()
        return ""

    def post_upload(self):
        data = self.read_json()
        if data is None:
            return self.send_json(400, {"error": "Invalid JSON"})

        csv_text = data.get("csvText")
        if not isinstance(csv_text, str) or not csv_text.strip():
            return self.send_json(400, {"error": "csvText is required"})

        conn = db_conn()
        default_agent_rate = float(setting(conn, "default_agent_commission_rate", "10"))
        default_agency_rate = float(setting(conn, "default_agency_commission_rate", "18"))

        agents = {
            row["display_name"].lower(): row["id"]
            for row in conn.execute("SELECT id, display_name FROM users WHERE role = 'agent'").fetchall()
        }

        created = 0
        reader = csv.DictReader(StringIO(csv_text))
        if not reader.fieldnames:
            conn.close()
            return self.send_json(400, {"error": "CSV has no headers"})

        normalized = {field: self.normalize_col(field) for field in reader.fieldnames}

        for raw_row in reader:
            row = {normalized[k]: (v or "") for k, v in raw_row.items()}

            date_raw = self.parse_csv_value(row, ["date", "date sold", "sold date"])
            customer = self.parse_csv_value(row, ["customer name", "name", "customer"])
            phone = self.parse_csv_value(row, ["contact", "phone", "number"])
            address = self.parse_csv_value(row, ["address"])
            policy_type = self.parse_csv_value(row, ["policy", "policy type", "line of business"])
            carrier = self.parse_csv_value(row, ["purchase company", "carrier", "company"])
            notes = self.parse_csv_value(row, ["notes", "updates"])
            premium_raw = self.parse_csv_value(
                row,
                ["premium", "premium amount", "total premium", "listed premium", "amount"],
            )
            salesperson_name = self.parse_csv_value(
                row,
                ["salesperson", "agent", "salesman", "employee"],
            ).lower()

            if not customer or not date_raw or not premium_raw:
                continue

            date_sold = ""
            for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y"):
                try:
                    date_sold = datetime.strptime(date_raw.strip(), fmt).strftime("%Y-%m-%d")
                    break
                except ValueError:
                    continue
            if not date_sold:
                continue

            cleaned = (
                premium_raw.replace("$", "")
                .replace(",", "")
                .replace("/month", "")
                .replace("per month", "")
                .replace("monthly", "")
                .strip()
            )
            try:
                premium = float(cleaned)
            except ValueError:
                continue
            if premium <= 0:
                continue

            salesperson_id = agents.get(salesperson_name)
            if not salesperson_id:
                salesperson_id = next(iter(agents.values()), None)
            if not salesperson_id:
                continue

            now = datetime.utcnow().isoformat(timespec="seconds")
            conn.execute(
                """
                INSERT INTO sales(
                    salesperson_id, customer_name, phone, address, date_sold,
                    policy_type, carrier, premium_amount,
                    agent_commission_rate, agency_commission_rate, notes, created_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    salesperson_id,
                    customer,
                    phone,
                    address,
                    date_sold,
                    policy_type,
                    carrier,
                    premium,
                    default_agent_rate,
                    default_agency_rate,
                    notes,
                    now,
                ),
            )
            created += 1

        conn.commit()
        conn.close()
        return self.send_json(200, {"ok": True, "created": created})

    def export_sales(self, query):
        month = self.parse_month(query)
        conn = db_conn()
        rows = conn.execute(
            """
            SELECT
                s.date_sold,
                u.display_name AS salesperson,
                s.customer_name,
                s.phone,
                s.address,
                s.policy_type,
                s.carrier,
                s.premium_amount,
                s.agent_commission_rate,
                s.agency_commission_rate,
                ROUND(s.premium_amount * s.agent_commission_rate / 100.0, 2) AS agent_commission_amount,
                ROUND(s.premium_amount * s.agency_commission_rate / 100.0, 2) AS agency_commission_amount,
                s.notes
            FROM sales s
            JOIN users u ON u.id = s.salesperson_id
            WHERE substr(s.date_sold, 1, 7) = ?
            ORDER BY s.date_sold DESC, s.id DESC
            """,
            (month,),
        ).fetchall()
        conn.close()

        headers = [
            "date_sold",
            "salesperson",
            "customer_name",
            "phone",
            "address",
            "policy_type",
            "carrier",
            "premium_amount",
            "agent_commission_rate",
            "agency_commission_rate",
            "agent_commission_amount",
            "agency_commission_amount",
            "notes",
        ]

        stream = StringIO()
        writer = csv.DictWriter(stream, fieldnames=headers)
        writer.writeheader()
        for row in rows:
            writer.writerow(dict(row))

        filename = f"crm_sales_{month}.csv"
        return self.send_text(
            200,
            stream.getvalue(),
            content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    def serve_static(self, path):
        if path == "/":
            path = "/index.html"

        requested = os.path.normpath(path.lstrip("/"))
        full = os.path.abspath(os.path.join(STATIC_DIR, requested))
        static_root = os.path.abspath(STATIC_DIR)

        if not full.startswith(static_root):
            return self.send_text(403, "Forbidden")

        if not os.path.exists(full) or not os.path.isfile(full):
            # Use SPA fallback only for path-like routes, never for static assets.
            if "." in os.path.basename(requested):
                return self.send_text(404, "Not found")
            full = os.path.join(STATIC_DIR, "index.html")

        ext = os.path.splitext(full)[1].lower()
        type_overrides = {
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".html": "text/html; charset=utf-8",
            ".csv": "text/csv; charset=utf-8",
        }
        ctype, _ = mimetypes.guess_type(full)
        ctype = type_overrides.get(ext, ctype)
        if not ctype:
            ctype = "application/octet-stream"

        with open(full, "rb") as f:
            data = f.read()

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if full.endswith(".js") or full.endswith(".css"):
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def run_server():
    init_db()
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), CRMHandler)
    print(f"CRM server running on http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
