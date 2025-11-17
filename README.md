# Password50
#### Video Demo: [DEMO URL](https://youtu.be/RPW19hCJn6E)
#### Description:

Password50 is a secure, full stack password manager that I built for my CS50 final project. I wanted it to feel like something I’d actually use, not just a quick assignment. The app lets users register, log in, and store encrypted passwords for the different sites they use. Once you’re signed in, you can add new entries, edit them, delete them, change your master password, and quickly filter everything with a search bar.

All vault entries are encrypted using Fernet symmetric encryption before they ever hit the database, and all master passwords are hashed using Werkzeug. The whole project combines the main things we learned in CS50 — Flask, SQL, sessions, templating, and backend security — into one clean and functional application.

---

## How the App Works

When someone registers, the server checks if the username is already taken. If not, the master password is hashed and stored in the `users` table. The plain password is never stored anywhere. After logging in, the user’s `user_id` goes into the Flask session, and that’s how the app knows which vault entries to show.

### Adding Password Entries

To save a site’s login info, the user enters:
- Site name  
- Username for that site  
- Password to store  
- Optional notes  

Before saving anything, the password is encrypted with a Fernet key (loaded through `.env` using `python-dotenv`). The database only ever stores the encrypted version. When the vault loads, the server decrypts each password in memory so the user can read it, but the decrypted text never gets written back.

### Editing and Removing Entries

When editing an entry, the app:

1. Gets the entry that matches both the entry ID and the logged in user  
2. Decrypts the password  
3. Shows an editable form with the current data  
4. Re-encrypts and updates the record when the form is submitted  

Removing simply deletes the row after confirming ownership. All SQL uses CS50’s parameterized queries, so there’s no injection risk.

### Searching

The vault has a simple JavaScript search bar. As you type, entries that don’t match the text get hidden. It’s a small feature, but it genuinely makes the app easier to use when you have a bunch of entries saved.

### Changing Master Password

On the `/change` page, users can update their master password by providing:
- The current password  
- A new password  
- Confirmation of the new password  

The server checks the old hash and, if correct, replaces it with a new one. After changing your password, you get logged out for security.

---

## Database Schema

The app uses a SQLite database named **`password_manager.db`**.

### `users` Table

- `id` — primary key  
- `username` — unique username  
- `master_hash` — hashed master password  

### `passwords` Table

- `id` — primary key  
- `user_id` — foreign key referencing `users.id`  
- `site` — name of the site or app  
- `site_username` — username for that site  
- `encrypted_password` — Fernet-encrypted ciphertext  
- `notes` — optional notes  
- `created_at` — timestamp  

Each password row belongs to exactly one user. Even if someone got the database file, they’d only see encrypted password strings.

---

## File Structure

Here’s what the main files do:

### `app.py`

Handles:
- All the routes (login, logout, register, vault, add, edit, remove, change)  
- Session setup  
- Database queries  
- Input validation  
- Calling helper functions for encryption/decryption  

Everything that should be protected is wrapped with the `login_required` decorator.

### `helpers.py`

Contains the core utilities:
- `encrypt_password()` — Fernet encryption  
- `decrypt_password()` — Fernet decryption  
- `apology()` — CS50-style apology page  
- `login_required()` — makes sure the user is logged in  

The Fernet key is loaded from the `.env` file at startup.

### Templates (`templates/` folder)

All HTML pages written with Jinja2:

- `layout.html` — navbar + base layout  
- `index.html` — homepage after login  
- `login.html`  
- `register.html`  
- `vault.html` — the main vault view + search bar  
- `add.html`  
- `edit.html`  
- `change.html`  
- `apology.html`  

### Static Files (`static/`)

Only contains CSS. Bootstrap handles most of the layout, and my CSS tweaks the spacing and styling to make things cleaner.

### `requirements.txt`

Dependencies needed to run the app:

- Flask  
- Flask-Session  
- cs50  
- cryptography  
- python-dotenv  
- Werkzeug  

---

## Design Choices

One of the decisions I thought about was encryption. I chose to use one Fernet key for all entries instead of generating separate keys per user. For a project at this scale, one key keeps things simple and still provides strong security.

I also stuck with server-side rendering using Jinja rather than trying to build a full SPA. That lined up with the rest of the course and made everything easier to debug and maintain.

I added the optional notes field and timestamp to the `passwords` table just to make it feel a bit more like a real password manager rather than bare minimum functionality.

---

## What I Learned

Building Password50 gave me solid experience with:
- Handling passwords securely  
- Encryption and key management  
- Flask routing and sessions  
- SQL and database schema design  
- Working with templates  
- Validating user input  
- Debugging across the full stack  

Overall, I’m really happy with how Password50 turned out. It’s functional, realistic, and honestly something I could build on later. If I decide to keep working on it, I’d probably add a password generator, categories/tags, and maybe export/import features. But for CS50, it does exactly what I wanted and helped me learn full stack development more deeply.