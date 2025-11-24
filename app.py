from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, Response
)
import sqlite3
from datetime import datetime
import json
import os
import functools

from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

DB_PATH = "annapurna.db"

# Simple secret key + admin password
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "secretkey")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("admin_login", next=request.path))
        return view(**kwargs)
    return wrapped_view

def create_admin_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    password_hash = generate_password_hash(password)
    try:
        c.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
        print(f"Admin user '{username}' created.")
    except sqlite3.IntegrityError:
        print(f"Admin user '{username}' already exists.")
    finally:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Admins table for real login
    c.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    # Customers table: one row per phone number
    c.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            phone TEXT PRIMARY KEY,
            name TEXT
        )
    """)

    # Orders table: each order placed from the website
    c.execute("""
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT NOT NULL,
            created_at TEXT NOT NULL,
            total REAL NOT NULL,
            data TEXT NOT NULL,  -- JSON with items, notes, pickup, etc.
            FOREIGN KEY (phone) REFERENCES customers(phone)
        )
    """)

    # Payments table: admin records payments against a phone number
    c.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT NOT NULL,
            created_at TEXT NOT NULL,
            amount REAL NOT NULL,
            note TEXT,
            FOREIGN KEY (phone) REFERENCES customers(phone)
        )
    """)

    # Menu config table: single row with id=1
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS menu_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            menu_json TEXT NOT NULL,
            week_text TEXT,
            special_note TEXT,
            cutoff_monday TEXT,
            cutoff_tuesday TEXT,
            cutoff_wednesday TEXT,
            cutoff_thursday TEXT,
            cutoff_friday TEXT
        )
        """
    )


    conn.commit()

    # 🔹 Ensure at least one admin user exists
    c.execute("SELECT COUNT(*) FROM admins")
    count = c.fetchone()[0]
    conn.close()

    if count == 0:
        # Use env vars if set, otherwise defaults
        username = os.environ.get("ADMIN_USERNAME", "annapurna")
        password = os.environ.get("ADMIN_PASSWORD", "Annapurnas213!")
        create_admin_user(username, password)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --- Menu config storage helpers ---


def get_or_create_menu_config():
    """Fetch menu config row (id=1). If none, return an 'empty' structure."""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM menu_config WHERE id = 1")
    row = c.fetchone()
    conn.close()

    if row:
        return {
            "menu_json": row["menu_json"],
            "week_text": row["week_text"] or "",
            "special_note": row["special_note"] or "",
            "cutoffs": {
                "Monday": row["cutoff_monday"] or "",
                "Tuesday": row["cutoff_tuesday"] or "",
                "Wednesday": row["cutoff_wednesday"] or "",
                "Thursday": row["cutoff_thursday"] or "",
                "Friday": row["cutoff_friday"] or "",
            },
        }

    # No row yet – frontend will fall back to its own defaults
    return {
        "menu_json": "",
        "week_text": "",
        "special_note": "",
        "cutoffs": {
            "Monday": "",
            "Tuesday": "",
            "Wednesday": "",
            "Thursday": "",
            "Friday": "",
        },
    }


def save_menu_config(payload: dict):
    conn = get_db()
    c = conn.cursor()
    c.execute(
        """
        INSERT INTO menu_config (
            id, menu_json, week_text, special_note,
            cutoff_monday, cutoff_tuesday, cutoff_wednesday,
            cutoff_thursday, cutoff_friday
        )
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            menu_json = excluded.menu_json,
            week_text = excluded.week_text,
            special_note = excluded.special_note,
            cutoff_monday = excluded.cutoff_monday,
            cutoff_tuesday = excluded.cutoff_tuesday,
            cutoff_wednesday = excluded.cutoff_wednesday,
            cutoff_thursday = excluded.cutoff_thursday,
            cutoff_friday = excluded.cutoff_friday
        """,
        (
            payload.get("menu_json", ""),
            payload.get("week_text", ""),
            payload.get("special_note", ""),
            payload.get("cutoffs", {}).get("Monday", ""),
            payload.get("cutoffs", {}).get("Tuesday", ""),
            payload.get("cutoffs", {}).get("Wednesday", ""),
            payload.get("cutoffs", {}).get("Thursday", ""),
            payload.get("cutoffs", {}).get("Friday", ""),
        ),
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    # Serve your existing index.html (put it in templates folder)
    return render_template("index.html")


@app.route("/health")
def health():
    """Health check endpoint for Render.com"""
    return jsonify({"status": "ok"}), 200


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, username, password_hash FROM admins WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row["password_hash"], password):
            session["admin_logged_in"] = True
            session["admin_username"] = row["username"]
            next_url = request.args.get("next") or url_for("admin_page")
            return redirect(next_url)
        else:
            error = "Invalid username or password."

    return render_template("admin_login.html", error=error)


@app.route("/api/admin/admins", methods=["GET"])
@login_required
def list_admins():
    """
    Return a simple list of admin users (id + username).
    No passwords are returned for security reasons.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, username FROM admins ORDER BY username")
    rows = c.fetchall()
    conn.close()

    admins = [{"id": row["id"], "username": row["username"]} for row in rows]
    return jsonify(admins)


@app.route("/api/admin/admins", methods=["POST"])
@login_required
def create_admin():
    """
    Create a new admin user from JSON: { "username": "...", "password": "..." }
    """
    data = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    if len(password) < 6:
        return jsonify({"error": "Password should be at least 6 characters."}), 400

    conn = get_db()
    c = conn.cursor()
    password_hash = generate_password_hash(password)

    try:
        c.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already exists."}), 400

    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/admin/menu_config", methods=["GET", "POST"])
@login_required
def admin_menu_config():
    """Admin view/edit of menu config."""
    if request.method == "GET":
        cfg = get_or_create_menu_config()
        return jsonify(cfg)

    # POST: save
    data = request.get_json() or {}

    # Basic validation: ensure menu_json parses as JSON
    try:
        json.loads(data.get("menu_json", ""))
    except json.JSONDecodeError:
        return jsonify({"error": "Menu JSON is not valid JSON."}), 400

    save_menu_config(data)
    return jsonify({"status": "ok"})


@app.route("/api/menu_config", methods=["GET"])
def public_menu_config():
    """Public endpoint for the website to fetch current menu config."""
    cfg = get_or_create_menu_config()
    return jsonify(cfg)



@app.route("/admin/logout")
@login_required
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))



@app.route("/admin")
@login_required
def admin_page():
    # Simple admin dashboard
    return render_template("admin.html")


# ========= API ENDPOINTS =========

@app.route("/api/order", methods=["POST"])
def api_order():
    """
    Called from the frontend when the user clicks "Send Order on WhatsApp".
    Saves the order info to DB before opening WhatsApp.
    """
    data = request.get_json(force=True)

    # Expected payload from frontend
    name = data.get("name", "").strip()
    phone = data.get("phone", "").strip()
    pickup = data.get("pickupOption", "").strip()
    notes = data.get("notes", "").strip()
    items = data.get("items", [])
    total = float(data.get("total", 0.0))

    if not phone:
        return jsonify({"error": "Phone is required"}), 400

    # Upsert customer
    conn = get_db()
    c = conn.cursor()

    c.execute("SELECT phone FROM customers WHERE phone = ?", (phone,))
    row = c.fetchone()
    if row is None:
        c.execute(
            "INSERT INTO customers (phone, name) VALUES (?, ?)",
            (phone, name)
        )
    else:
        # Optionally update name if changed
        if name:
            c.execute(
                "UPDATE customers SET name = ? WHERE phone = ?",
                (name, phone)
            )

    # Prepare order JSON (store full payload for later review)
    order_payload = {
        "name": name,
        "phone": phone,
        "pickupOption": pickup,
        "notes": notes,
        "items": items,
        "total": total,
    }

    c.execute(
        "INSERT INTO orders (phone, created_at, total, data) VALUES (?, ?, ?, ?)",
        (
            phone,
            datetime.utcnow().isoformat(),   # store in UTC
            total,
            json.dumps(order_payload),
        ),
    )

    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})

@app.route("/api/admin/summary_csv", methods=["GET"])
@login_required
def admin_summary_csv():
    """
    Export monthly summary (per customer) as CSV.
    Query param: month=YYYY-MM  e.g. 2024-11

    CSV columns:
      phone, name,
      total_ordered_YYYY-MM,
      total_paid_YYYY-MM,
      balance_lifetime
    """
    month = request.args.get("month", "").strip()  # "2024-11"
    if not month or len(month) != 7 or month[4] != "-":
        return jsonify({"error": "month param required in format YYYY-MM"}), 400

    conn = get_db()
    c = conn.cursor()

    # We compute:
    # - total ordered in this month (orders)
    # - total paid in this month (payments)
    # - total ordered all time
    # - total paid all time
    # Then balance_lifetime = total_ordered_all - total_paid_all
    c.execute("""
        SELECT
            c.phone,
            COALESCE(c.name, '') AS name,
            -- monthly ordered
            COALESCE((
                SELECT SUM(o.total)
                FROM orders o
                WHERE o.phone = c.phone
                  AND substr(o.created_at, 1, 7) = ?
            ), 0) AS total_ordered_month,
            -- monthly paid
            COALESCE((
                SELECT SUM(p.amount)
                FROM payments p
                WHERE p.phone = c.phone
                  AND substr(p.created_at, 1, 7) = ?
            ), 0) AS total_paid_month,
            -- lifetime ordered
            COALESCE((
                SELECT SUM(o2.total)
                FROM orders o2
                WHERE o2.phone = c.phone
            ), 0) AS total_ordered_all,
            -- lifetime paid
            COALESCE((
                SELECT SUM(p2.amount)
                FROM payments p2
                WHERE p2.phone = c.phone
            ), 0) AS total_paid_all
        FROM customers c
        ORDER BY c.phone
    """, (month, month))
    rows = c.fetchall()
    conn.close()

    header = f"phone,name,total_ordered_{month},total_paid_{month},balance_lifetime"
    lines = [header]

    for r in rows:
        total_ordered_month = round(r["total_ordered_month"], 2)
        total_paid_month = round(r["total_paid_month"], 2)
        total_ordered_all = round(r["total_ordered_all"], 2)
        total_paid_all = round(r["total_paid_all"], 2)
        balance_lifetime = total_ordered_all - total_paid_all

        phone = r["phone"]
        name = (r["name"] or "").replace('"', '""')  # basic escaping

        lines.append(
            f'{phone},"{name}",'
            f'{total_ordered_month:.2f},'
            f'{total_paid_month:.2f},'
            f'{balance_lifetime:.2f}'
        )

    csv_data = "\n".join(lines) + "\n"
    filename = f"annapurna_monthly_summary_{month}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.route("/api/admin/summary", methods=["GET"])
@login_required
def admin_summary():
    """
    Returns customer-level summary:
    phone, name, total_ordered, total_paid, balance
    """
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT
            c.phone,
            COALESCE(c.name, '') AS name,
            COALESCE( SUM(o.total), 0 ) AS total_ordered,
            COALESCE( (
                SELECT SUM(p.amount)
                FROM payments p
                WHERE p.phone = c.phone
            ), 0 ) AS total_paid
        FROM customers c
        LEFT JOIN orders o ON o.phone = c.phone
        GROUP BY c.phone, c.name
        ORDER BY c.phone
    """)

    rows = c.fetchall()
    conn.close()

    result = []
    for r in rows:
        total_ordered = r["total_ordered"]
        total_paid = r["total_paid"]
        balance = total_ordered - total_paid
        result.append({
            "phone": r["phone"],
            "name": r["name"],
            "total_ordered": round(total_ordered, 2),
            "total_paid": round(total_paid, 2),
            "balance": round(balance, 2),
        })

    return jsonify(result)


@app.route("/api/admin/orders", methods=["GET"])
@login_required
def admin_orders():
    """
    Returns list of orders for a specific phone.
    """
    phone = request.args.get("phone", "").strip()
    if not phone:
        return jsonify({"error": "phone is required"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        SELECT id, created_at, total, data
        FROM orders
        WHERE phone = ?
        ORDER BY created_at DESC
    """, (phone,))
    rows = c.fetchall()
    conn.close()

    orders = []
    for r in rows:
        try:
            payload = json.loads(r["data"])
        except Exception:
            payload = {}
        orders.append({
            "id": r["id"],
            "created_at": r["created_at"],
            "total": r["total"],
            "data": payload,
        })

    return jsonify(orders)


@app.route("/api/admin/payments", methods=["GET", "POST"])
@login_required
def admin_payments():
    """
    GET: list payments for a phone.
    POST: add a new payment {phone, amount, note}
    """
    if request.method == "GET":
        phone = request.args.get("phone", "").strip()
        if not phone:
            return jsonify({"error": "phone is required"}), 400

        conn = get_db()
        c = conn.cursor()
        c.execute("""
            SELECT id, created_at, amount, note
            FROM payments
            WHERE phone = ?
            ORDER BY created_at DESC
        """, (phone,))
        rows = c.fetchall()
        conn.close()

        payments = [
            {
                "id": r["id"],
                "created_at": r["created_at"],
                "amount": r["amount"],
                "note": r["note"] or "",
            }
            for r in rows
        ]
        return jsonify(payments)

    # POST
    data = request.get_json(force=True)
    phone = data.get("phone", "").strip()
    amount = float(data.get("amount", 0.0))
    note = data.get("note", "").strip()

    if not phone:
        return jsonify({"error": "phone is required"}), 400
    if amount <= 0:
        return jsonify({"error": "amount must be > 0"}), 400

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO payments (phone, created_at, amount, note)
        VALUES (?, ?, ?, ?)
    """, (
        phone,
        datetime.utcnow().isoformat(),
        amount,
        note
    ))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok"})


# Ensure DB and default admin exist when app imports (including on Render)
init_db()

if __name__ == "__main__":
    # local dev
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
