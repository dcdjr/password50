# ----------------------------
# Imports and Setup
# ----------------------------

import os
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet

# Import helper functions (encryption, decryption, login check, etc.)
from helpers import encrypt_password, decrypt_password, apology, login_required


# ----------------------------
# Flask Configuration
# ----------------------------

app = Flask(__name__)

# Make sure sessions are stored in the filesystem (not cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Connect to database
db = SQL("sqlite:///password_manager.db")


# ----------------------------
# Cache Control
# ----------------------------

@app.after_request
def after_request(response):
    """This makes sure that the browser doesn't cache old pages"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# ----------------------------
# Routes
# ----------------------------

@app.route("/")
@login_required
def index():
    """Home page after logging in"""
    return render_template("index.html")


# ----------------------------
# Edit Entry
# ----------------------------

@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit(id):
    """Edit a saved password entry"""
    # Get the entry for the logged-in user
    rows = db.execute(
        "SELECT * FROM passwords WHERE id = ? AND user_id = ?",
        id,
        session["user_id"],
    )

    # If entry not found, show error
    if len(rows) != 1:
        return apology("entry not found", 404)

    entry = rows[0]

    # Try to decrypt password, but handle errors
    try:
        entry["decrypted_password"] = decrypt_password(entry["encrypted_password"])
    except Exception:
        entry["decrypted_password"] = "[decryption failed]"

    # If form is submitted, update the entry
    if request.method == "POST":
        site = request.form.get("site")
        site_username = request.form.get("site_username")
        password = request.form.get("password")
        notes = request.form.get("notes")

        # Make sure required fields are filled in
        if not site or not password:
            return apology("missing fields", 400)

        # Encrypt password before saving
        encrypted_password = encrypt_password(password)

        # Update entry in database
        db.execute(
            """
            UPDATE passwords
            SET site = ?, site_username = ?, encrypted_password = ?, notes = ?
            WHERE id = ? AND user_id = ?
            """,
            site,
            site_username,
            encrypted_password,
            notes,
            id,
            session["user_id"],
        )

        flash("Entry updated successfully!")
        return redirect("/vault")

    # If GET request, show the edit page
    return render_template("edit.html", entry=entry)


# ----------------------------
# Vault (View All)
# ----------------------------

@app.route("/vault")
@login_required
def vault():
    """Show all saved passwords"""
    entries = db.execute(
        "SELECT * FROM passwords WHERE user_id = ?", session["user_id"]
    )

    # Try to decrypt each stored password
    for e in entries:
        try:
            e["decrypted"] = decrypt_password(e["encrypted_password"])
        except Exception:
            e["decrypted"] = "[error]"

    return render_template("vault.html", entries=entries)


# ----------------------------
# Remove Entry
# ----------------------------

@app.route("/remove", methods=["GET", "POST"])
@login_required
def remove():
    """Delete a password entry"""
    site = request.form.get("site")

    # Delete from database
    db.execute(
        "DELETE FROM passwords WHERE site = ? AND user_id = ?",
        site,
        session["user_id"],
    )

    flash("Password deleted successfully.")
    return redirect("/vault")


# ----------------------------
# Add Entry
# ----------------------------

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Add a new password entry"""
    if request.method == "POST":
        user_id = session["user_id"]
        site = request.form.get("site")
        site_username = request.form.get("site_username")
        password = request.form.get("password")
        notes = request.form.get("notes")

        # Make sure required fields are filled
        if not site or not password:
            return apology("missing fields", 400)

        # Encrypt password before storing
        encrypted_password = encrypt_password(password)

        # Insert into database
        db.execute(
            """
            INSERT INTO passwords (user_id, site, site_username, encrypted_password, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            user_id,
            site,
            site_username,
            encrypted_password,
            notes,
        )

        flash("Password added successfully!")
        return redirect("/vault")

    return render_template("add.html")


# ----------------------------
# Login / Logout / Register / Change Password
# ----------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log the user in"""
    # Clear any old session data
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check for missing fields
        if not username:
            return apology("must provide username", 403)
        if not password:
            return apology("must provide password", 403)

        # Find user in the database
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Verify username and password
        if len(rows) != 1 or not check_password_hash(rows[0]["master_hash"], password):
            return apology("invalid username and/or password", 403)

        # Save user session
        session["user_id"] = rows[0]["id"]
        return redirect("/")

    # Show login page if GET
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Log the user out"""
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check required fields
        if not username:
            return apology("must provide username", 400)
        if not password:
            return apology("must provide password", 400)
        if not confirmation:
            return apology("must confirm password", 400)
        if password != confirmation:
            return apology("passwords do not match", 400)

        # Make sure username isn’t already taken
        existing = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(existing) != 0:
            return apology("user already exists", 400)

        # Add new user to database with hashed password
        new_user_id = db.execute(
            "INSERT INTO users (username, master_hash) VALUES (?, ?)",
            username,
            generate_password_hash(password),
        )

        # Log in the new user automatically
        session["user_id"] = new_user_id
        return redirect("/")

    return render_template("register.html")


@app.route("/change", methods=["GET", "POST"])
@login_required
def change():
    """Change the master password"""
    if request.method == "POST":
        current = request.form.get("current_password")
        new = request.form.get("new_password")
        confirm = request.form.get("confirmed_new_password")

        # Check for missing fields
        if not current:
            return apology("must provide current password", 400)
        if not new:
            return apology("must provide new password", 400)
        if not confirm:
            return apology("must confirm new password", 400)
        if new != confirm:
            return apology("new password and confirm password fields must match", 400)

        # Verify the current password
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if len(rows) != 1 or not check_password_hash(rows[0]["master_hash"], current):
            return apology("invalid password", 400)

        # Update password hash
        db.execute(
            "UPDATE users SET master_hash = ? WHERE id = ?",
            generate_password_hash(new),
            session["user_id"],
        )

        # Log user out after password change
        session.clear()
        return redirect("/login")

    return render_template("change.html")
