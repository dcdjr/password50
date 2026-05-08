# Password50

> Educational project built for Harvard CS50. This is not intended to be used as a production password manager.

Video demo: [Password50 Demo](https://youtu.be/RPW19hCJn6E)

## Overview

Password50 is a full-stack password manager built with Flask, SQLite, Jinja templates, and Bootstrap.

The app lets users register, log in, and manage encrypted vault entries for different sites. It was built as a CS50 final project to practice authentication, database design, encryption, server-side rendering, and backend security fundamentals.

## Features

- User registration and login
- Session-based authentication
- Add, edit, search, and delete vault entries
- Encrypted stored passwords using Fernet symmetric encryption
- Hashed master passwords using Werkzeug
- SQLite database with user-owned vault records
- Server-side templates with Jinja
- Bootstrap-based interface

## Security Notes

This project is educational. It demonstrates important security concepts, but it should not be treated as a production password manager.

Current design choices include:

- Master passwords are hashed before storage
- Vault passwords are encrypted before being written to the database
- SQL queries use parameterized inputs
- Each vault entry is associated with the logged-in user
- The Fernet key is loaded from environment configuration

For a production-grade password manager, the design would need stronger key management, per-user key derivation, stricter session hardening, audit logging, recovery flows, secure deployment practices, and significantly more testing.

## How It Works

When a user registers, the server checks whether the username is available, hashes the master password, and stores the user record.

After login, the user's ID is stored in the Flask session. Vault routes use that session value to show and modify only the current user's entries.

When a user saves a site password, the app encrypts the password with Fernet before inserting it into SQLite. When the vault loads, encrypted passwords are decrypted in memory for display.

## Database Schema

The app uses a SQLite database named `password_manager.db`.

### `users`

- `id` — primary key
- `username` — unique username
- `master_hash` — hashed master password

### `passwords`

- `id` — primary key
- `user_id` — foreign key referencing `users.id`
- `site` — site or app name
- `site_username` — username for that site
- `encrypted_password` — Fernet-encrypted ciphertext
- `notes` — optional notes
- `created_at` — timestamp

## Project Structure

```text
app.py              Flask routes, sessions, validation, and database operations
helpers.py          Encryption/decryption helpers, login guard, and CS50 apology helper
templates/          Jinja templates for the app pages
static/             CSS and static assets
requirements.txt    Python dependencies
```

## What I Learned

This project gave me practical experience with:

- Flask routing and sessions
- Authentication flows
- Password hashing
- Symmetric encryption
- SQLite schema design
- CRUD operations
- Server-side rendering with Jinja
- Input validation and ownership checks
