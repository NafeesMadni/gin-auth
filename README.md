## Gin Auth & OAuth2 Project

This repository contains a robust, production-ready **Go (Gin)** authentication backend. It features standard email/password authentication, Google OAuth2 integration, and a sophisticated session management system with automated background cleanup.

---

### 🚀 Key Features

* **Secure Authentication:** Standard Signup/Login with password hashing.
* **Email Verification:** Integration with Gmail SMTP to verify user accounts via OTP.
* **Google OAuth2 Integration:** Seamless social login via Google.
* **Refresh Token Rotation:** High-security session management that rotates tokens on every refresh.
* **Hybrid Logout & Revocation:** Supports both stateful session deletion and stateless JTI blacklisting.
* **Automated Maintenance:** A background "janitor" goroutine that periodically purges expired sessions, blacklist entries, and unverified user accounts to optimize database performance.

---

### 🛠️ Tech Stack

* **Language:** Go (Golang)
* **Framework:** Gin Gonic
* **Database:** SQLite (via GORM)
* **Authentication:** JWT (v5), OAuth2, SMTP (Gmail)
* **Hot Reload:** Air

---

### 📂 Project Structure

```text
.
├── internals/
│   ├── controllers/  # Auth, OAuth, and User logic
│   ├── initializers/ # DB connection, and Cleanup tasks
│   ├── middleware/   # JWT verification and Blacklist checking
│   ├── models/       # GORM schemas (User, Session, Blacklist)
│   └── utils/        # Token generation, Emailing & helpers
├── main.go           # Application entry point
├── .air.toml         # Hot reload configuration
└── .env.example      # Environment variables example

```

---

### ⚙️ Getting Started

#### 1. Gmail SMTP Setup (Verification Emails)

To enable email verification, you must use a Google **App Password**. Regular passwords will be blocked by Google.

1. Enable **2-Step Verification** in your [Google Security Settings](https://www.google.com/search?q=https://myaccount.google.com/security).
2. Navigate to the **App Passwords** section: 👉 **[Generate App Password Here](https://www.google.com/search?q=https://myaccount.google.com/apppasswords)**.
3. Select `Other (Custom name)` and name it `Gin-Auth-App`.
4. Copy the **16-character code** and paste it into your `.env` (remove all spaces).

#### 2. Configuration

Create a `.env` file in the root directory:

```env
APP_NAME=your_app_name
PORT=3000
DB_URL=local.db
SECRET=your_jwt_signing_secret

# JWT & Cleanup Configuration
JWT_EXPIRATION_SECONDS=900
REFRESH_TOKEN_EXPIRATION_SECONDS=604800
CLEANUP_INTERVAL_MINUTES=30

# Security Configuration
COOKIE_SECURE=false # Set to true for production/HTTPS

# Google OAuth2 Credentials
GOOGLE_CLIENT_ID=your_client_id
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REDIRECT_URL=http://localhost:3000/auth/google/callback

# Gmail SMTP Configuration
GMAIL_USER=your_email@gmail.com
GMAIL_APP_PASSWORD=your_16_char_app_password
VERIFICATION_EXPIRATION_MINUTES=10

```

#### 3. Running the Project

```bash
# Development with hot reload
air

# Standard run
go run main.go

```

---

### 🧪 API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/` | Returns a 200 OK or API metadata (Health Check). |
| `POST` | `/signup` | Creates a new user account and sends a 6-digit verification code. |
| `POST` | `/verify` | Validates the email OTP code and activates the user account. |
| `POST` | `/login` | Authenticates verified users and issues stateful session cookies. |
| `GET` | `/auth/google/login` | Initiates the Google OAuth2 flow. |
| `GET` | `/auth/google/callback` | Handles Google response and issues local session tokens. |
| `POST` | `/auth/refresh` | **Rotation**: Replaces the current Refresh Token with a new pair. |
| `POST` | `/logout` | **Revocation**: Deletes DB session and blacklists the current JTI. |
| `GET` | `/validate` | Middleware-protected route to verify the active Authorization token. |

---

### 🧹 Database Maintenance

The project includes an automated **Background Janitor** that ensures the SQLite database stays small and fast. Every `CLEANUP_INTERVAL_MINUTES`, the janitor performs the following:

* **Session Purge:** Permanently deletes rows in the `sessions` table where `expires_at < now`.
* **Blacklist Purge:** Removes entries in the `blacklists` table once the Access Token's natural lifespan has ended.
* **User Cleanup:** Removes unverified accounts that have not completed the email verification flow within 24 hours.

---

### 🔑 OAuth2 Setup Reference

For a step-by-step guide on how to configure your Google Cloud Console, refer to the:
👉 **[Google OAuth2 Setup Guide](./docs/GOOGLE_OAUTH_SETUP.md)**