import os
import sqlite3
import secrets
from decimal import Decimal, InvalidOperation
from datetime import timedelta

from flask import (
    Flask, render_template, request,
    redirect, session, flash, abort
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


# Load private settings from .env
load_dotenv()

secret_key = os.getenv("SECRET_KEY")

if not secret_key:
    raise RuntimeError(
        "SECRET_KEY is missing. Check your .env file."
    )


app = Flask(__name__)
app.secret_key = secret_key

# Session security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.getenv("FLASK_HTTPS_ONLY", "0") == "1"
)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
app.config["WTF_CSRF_TIME_LIMIT"] = 3600

# CSRF protection
csrf = CSRFProtect(app)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)


def database():
    db = sqlite3.connect("wallet.db")
    db.row_factory = sqlite3.Row
    return db


def log_activity(username, activity, details):
    db = database()

    db.execute("""
        INSERT INTO activity_logs (username, activity, details)
        VALUES (?, ?, ?)
    """, (username, activity, details))

    db.commit()
    db.close()


def generate_account_number(db):
    while True:
        number = str(
            secrets.randbelow(9000000000) + 1000000000
        )

        exists = db.execute(
            "SELECT id FROM users WHERE account_number=?",
            (number,)
        ).fetchone()

        if not exists:
            return number


def setup():
    db = database()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            balance INTEGER DEFAULT 0,
            account_number TEXT
        )
    """)

    columns = [
        row["name"]
        for row in db.execute(
            "PRAGMA table_info(users)"
        ).fetchall()
    ]

    if "account_number" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN account_number TEXT"
        )

    if "transfer_pin_hash" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN transfer_pin_hash TEXT"
        )

    if "is_active" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1"
        )

    db.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            amount INTEGER,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            activity TEXT,
            details TEXT,
            date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Assign account numbers to older accounts if needed
    users = db.execute(
        "SELECT id FROM users WHERE account_number IS NULL"
    ).fetchall()

    for user in users:
        number = generate_account_number(db)

        db.execute(
            "UPDATE users SET account_number=? WHERE id=?",
            (number, user["id"])
        )

    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS
        unique_account_number ON users(account_number)
    """)

    db.commit()
    db.close()


@app.route("/")
def home():
    if "user" not in session:
        return redirect("/login")

    db = database()

    user = db.execute(
        "SELECT * FROM users WHERE username=?",
        (session["user"],)
    ).fetchone()

    if not user or not user["is_active"]:
        session.clear()
        db.close()
        flash("Your account is unavailable.")
        return redirect("/login")

    transactions = db.execute("""
        SELECT * FROM transactions
        WHERE sender=? OR receiver=?
        ORDER BY id DESC
        LIMIT 10
    """, (session["user"], session["user"])).fetchall()

    db.close()

    return render_template(
        "index.html",
        user=user,
        transactions=transactions
    )


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        if len(username) < 3 or len(password) < 6:
            flash("Username or password is too short.")
            return redirect("/register")

        db = database()

        try:
            number = generate_account_number(db)

            db.execute("""
                INSERT INTO users
                (username, password, account_number)
                VALUES (?, ?, ?)
            """, (
                username,
                generate_password_hash(password),
                number
            ))

            db.commit()
            db.close()

            log_activity(
                username,
                "Registration",
                "A new wallet account was created."
            )

            flash("Registration successful. Please log in.")
            return redirect("/login")

        except sqlite3.IntegrityError:
            db.close()
            flash("Username already exists.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = database()

        user = db.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        db.close()

        if user and check_password_hash(
            user["password"], password
        ):
            if not user["is_active"]:
                log_activity(
                    username,
                    "Failed login",
                    "Login blocked because the account is suspended."
                )

                flash("Your account has been suspended.")
                return redirect("/login")

            session.clear()
            session["user"] = username
            session.permanent = True

            log_activity(
                username,
                "Successful login",
                "User logged in successfully."
            )

            return redirect("/")

        log_activity(
            username,
            "Failed login",
            "Incorrect username or password."
        )

        flash("Invalid login details.")

    return render_template("login.html")


@app.route("/set-pin", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def set_pin():
    if "user" not in session:
        return redirect("/login")

    db = database()

    user = db.execute(
        "SELECT is_active FROM users WHERE username=?",
        (session["user"],)
    ).fetchone()

    if not user or not user["is_active"]:
        db.close()
        session.clear()
        flash("Your account is unavailable.")
        return redirect("/login")

    db.close()

    if request.method == "POST":
        pin = request.form.get("pin", "")

        if len(pin) != 4 or not pin.isdigit():
            flash("PIN must contain exactly 4 digits.")
            return redirect("/set-pin")

        db = database()

        db.execute(
            "UPDATE users SET transfer_pin_hash=? WHERE username=?",
            (
                generate_password_hash(pin),
                session["user"]
            )
        )

        db.commit()
        db.close()

        log_activity(
            session["user"],
            "PIN updated",
            "User created or changed their transfer PIN."
        )

        flash("Transfer PIN created successfully!")
        return redirect("/")

    return render_template("set_pin.html")


@app.route("/send", methods=["POST"])
@limiter.limit("10 per minute")
def send():
    if "user" not in session:
        return redirect("/login")

    receiver_number = request.form["receiver"].strip()
    pin = request.form.get("pin", "")

    try:
        entered_amount = Decimal(request.form["amount"])

        if entered_amount <= 0:
            raise ValueError("Invalid amount.")

        if entered_amount.as_tuple().exponent < -2:
            raise ValueError("Amount cannot have more than 2 decimal places.")

        amount = int(entered_amount * 100)

    except (ValueError, TypeError, InvalidOperation):
        amount = 0

    sender = session["user"]

    if amount <= 0:
        log_activity(
            sender,
            "Failed transfer",
            "Invalid transfer amount."
        )

        flash("Enter a valid amount.")
        return redirect("/")

    db = database()

    try:
        db.execute("BEGIN IMMEDIATE")

        sender_data = db.execute(
            "SELECT * FROM users WHERE username=?",
            (sender,)
        ).fetchone()

        if not sender_data or not sender_data["is_active"]:
            raise ValueError("Your account is unavailable.")

        if not sender_data["transfer_pin_hash"]:
            raise ValueError(
                "Please create your transfer PIN first."
            )

        if not check_password_hash(
            sender_data["transfer_pin_hash"], pin
        ):
            raise ValueError("Incorrect transfer PIN.")

        receiver_data = db.execute(
            "SELECT * FROM users WHERE account_number=?",
            (receiver_number,)
        ).fetchone()

        if not receiver_data:
            raise ValueError("Account number not found.")

        if not receiver_data["is_active"]:
            raise ValueError("Recipient account is suspended.")

        if sender_data["id"] == receiver_data["id"]:
            raise ValueError(
                "You cannot send money to yourself."
            )

        if sender_data["balance"] < amount:
            raise ValueError("Insufficient balance.")

        db.execute(
            "UPDATE users SET balance=balance-? WHERE username=?",
            (amount, sender)
        )

        db.execute(
            "UPDATE users SET balance=balance+? WHERE id=?",
            (amount, receiver_data["id"])
        )

        db.execute("""
            INSERT INTO transactions (sender, receiver, amount)
            VALUES (?, ?, ?)
        """, (
            sender,
            receiver_data["username"],
            amount
        ))

        db.commit()

        log_activity(
            sender,
            "Successful transfer",
            f"Sent ₦{amount / 100:,.2f} to {receiver_data['username']}."
        )

        flash("Transfer successful!")

    except (ValueError, sqlite3.Error) as error:
        db.rollback()

        log_activity(
            sender,
            "Failed transfer",
            str(error)
        )

        flash(str(error))

    finally:
        db.close()

    return redirect("/")


@app.route("/topup", methods=["POST"])
@limiter.limit("5 per minute")
def topup():
    if "user" not in session:
        return redirect("/login")

    db = database()

    user = db.execute(
        "SELECT is_active FROM users WHERE username=?",
        (session["user"],)
    ).fetchone()

    if not user or not user["is_active"]:
        db.close()
        session.clear()
        flash("Your account is unavailable.")
        return redirect("/login")

    amount = 1000000

    db.execute(
        "UPDATE users SET balance=balance+? WHERE username=?",
        (amount, session["user"])
    )

    db.execute("""
        INSERT INTO transactions (sender, receiver, amount)
        VALUES (?, ?, ?)
    """, ("DEMO", session["user"], amount))

    db.commit()
    db.close()

    log_activity(
        session["user"],
        "Demo top-up",
        "Added ₦10,000 in simulated funds."
    )

    flash("₦10,000 demo funds added!")
    return redirect("/")


@app.route("/admin", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = database()

        admin = db.execute(
            "SELECT * FROM admins WHERE username=?",
            (username,)
        ).fetchone()

        db.close()

        if admin and check_password_hash(
            admin["password_hash"], password
        ):
            session.clear()
            session["admin"] = admin["username"]
            session.permanent = True

            log_activity(
                username,
                "Admin login",
                "Administrator logged in successfully."
            )

            return redirect("/admin/dashboard")

        log_activity(
            username,
            "Failed admin login",
            "Incorrect administrator login details."
        )

        flash("Invalid administrator login details.")

    return render_template("admin_login.html")


@app.route("/admin/dashboard")
def admin_dashboard():
    if "admin" not in session:
        return redirect("/admin")

    search_term = request.args.get("search", "").strip()

    db = database()

    total_users = db.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    active_users = db.execute(
        "SELECT COUNT(*) FROM users WHERE is_active=1"
    ).fetchone()[0]

    suspended_users = db.execute(
        "SELECT COUNT(*) FROM users WHERE is_active=0"
    ).fetchone()[0]

    total_balance = db.execute(
        "SELECT SUM(balance) FROM users"
    ).fetchone()[0] or 0

    transaction_stats = db.execute("""
        SELECT
            COUNT(*) AS total_transactions,
            COALESCE(SUM(amount), 0) AS total_volume
        FROM transactions
        WHERE sender != 'DEMO'
    """).fetchone()

    failed_transfers = db.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE activity='Failed transfer'
    """).fetchone()[0]

    today_registrations = db.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE activity='Registration'
        AND date(date)=date('now')
    """).fetchone()[0]

    today_logins = db.execute("""
        SELECT COUNT(*)
        FROM activity_logs
        WHERE activity='Successful login'
        AND date(date)=date('now')
    """).fetchone()[0]

    users = db.execute("""
        SELECT id, username, account_number, balance, is_active
        FROM users
        WHERE username LIKE ? OR account_number LIKE ?
        ORDER BY id DESC
    """, (
        f"%{search_term}%",
        f"%{search_term}%"
    )).fetchall()

    transactions = db.execute(
        "SELECT * FROM transactions ORDER BY id DESC"
    ).fetchall()

    activity_logs = db.execute("""
        SELECT * FROM activity_logs
        ORDER BY id DESC
        LIMIT 100
    """).fetchall()

    db.close()

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        active_users=active_users,
        suspended_users=suspended_users,
        total_balance=total_balance,
        total_transactions=transaction_stats["total_transactions"],
        total_volume=transaction_stats["total_volume"],
        failed_transfers=failed_transfers,
        today_registrations=today_registrations,
        today_logins=today_logins,
        users=users,
        transactions=transactions,
        search_term=search_term,
        activity_logs=activity_logs
    )


@app.route("/admin/user-status/<int:user_id>", methods=["POST"])
def admin_user_status(user_id):
    if "admin" not in session:
        return redirect("/admin")

    action = request.form.get("action")

    if action not in ["suspend", "activate"]:
        abort(400)

    status = 0 if action == "suspend" else 1

    db = database()

    result = db.execute(
        "UPDATE users SET is_active=? WHERE id=?",
        (status, user_id)
    )

    affected_user = db.execute(
        "SELECT username FROM users WHERE id=?",
        (user_id,)
    ).fetchone()

    db.commit()
    db.close()

    if result.rowcount and affected_user:
        if action == "suspend":
            log_activity(
                session["admin"],
                "Account suspended",
                f"Suspended user {affected_user['username']}."
            )

            flash("User account suspended.")

        else:
            log_activity(
                session["admin"],
                "Account reactivated",
                f"Reactivated user {affected_user['username']}."
            )

            flash("User account reactivated.")

    else:
        flash("User account not found.")

    return redirect("/admin/dashboard")

@app.route("/admin/user-credit/<int:user_id>", methods=["POST"])
@limiter.limit("20 per hour")
def admin_user_credit(user_id):

    if "admin" not in session:
        return redirect("/admin")

    raw_amount = request.form.get("amount", "").strip()
    note = request.form.get("note", "").strip()

    try:
        entered_amount = Decimal(raw_amount)

        if not entered_amount.is_finite() or entered_amount <= 0:
            raise ValueError("Enter a valid funding amount.")

        if entered_amount.as_tuple().exponent < -2:
            raise ValueError("Maximum of 2 decimal places allowed.")

        amount = int(entered_amount * 100)

    except (ValueError, InvalidOperation):
        flash("Please enter a valid funding amount.")
        return redirect("/admin/dashboard")

    db = database()

    try:
        db.execute("BEGIN IMMEDIATE")

        user = db.execute(
            "SELECT * FROM users WHERE id=?",
            (user_id,)
        ).fetchone()

        if not user:
            raise ValueError("User account not found.")

        if not user["is_active"]:
            raise ValueError("Cannot fund a suspended account.")

        db.execute(
            "UPDATE users SET balance=balance+? WHERE id=?",
            (amount, user_id)
        )

        db.execute("""
            INSERT INTO transactions (sender, receiver, amount)
            VALUES (?, ?, ?)
        """, ("OWNER", user["username"], amount))

        db.commit()

        log_activity(
            session["admin"],
            "Owner wallet funding",
            f"Added ₦{amount / 100:,.2f} to "
            f"{user['username']}. Note: {note or 'No note provided'}"
        )

        flash(
            f"Successfully added ₦{amount / 100:,.2f} "
            f"to {user['username']}'s wallet."
        )

    except (ValueError, sqlite3.Error) as error:
        db.rollback()
        flash(str(error))

    finally:
        db.close()

    return redirect("/admin/dashboard")
@app.route("/admin/logout")
def admin_logout():
    admin = session.get("admin")

    if admin:
        log_activity(
            admin,
            "Admin logout",
            "Administrator logged out."
        )

    session.clear()
    flash("Administrator logged out successfully.")
    return redirect("/admin")


@app.route("/logout")
def logout():
    username = session.get("user")

    if username:
        log_activity(
            username,
            "User logout",
            "User logged out."
        )

    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    setup()

    app.run(
        debug=os.getenv("FLASK_DEBUG", "0") == "1"
    )
