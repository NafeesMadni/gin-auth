## Gin Auth & OAuth2 Project

This repository contains a robust, production-ready **Go (Gin)** authentication backend. It features standard email/password authentication, Google OAuth2 integration, and a sophisticated session management system with automated background cleanup.

---

### 🚀 Key Features

* **Multi-Factor Authentication (2FA):** Secure TOTP (Time-based One-Time Password) implementation with AES-256-GCM encryption for secrets at rest.
* **Secure Authentication:** Standard Signup/Login with password hashing using Bcrypt.
* **Two-Step Secure Login**: Enhanced `/login` flow that detects MFA status and requires a secondary verification step via `/2fa/login-verify` before issuing session cookies.
* **Email Verification:** Integration with Gmail SMTP to verify user accounts via OTP with built-in cooldown logic.
* **Signup Collision Handling:** Intelligent logic to handle duplicate registration attempts for verified vs. unverified users.
* **Google OAuth2:** Seamless social login integration.
* **Refresh Token Rotation:** High-security session management that rotates tokens on every refresh to prevent replay attacks.
* **Hybrid Logout:** Supports stateful session revocation and stateless JTI blacklisting.
* **Automated Maintenance:** Background "janitor" goroutine to purge expired sessions, blacklist entries, and abandoned unverified accounts.

---

### 🛠️ Tech Stack

* **Language:** Go (Golang)
* **Framework:** Gin Gonic
* **Database:** SQLite (via GORM)
* **Encryption:** AES-GCM (for 2FA secrets)
* **Authentication:** JWT, TOTP, OAuth2, SMTP (Gmail)
* **Hot Reload:** Air

---

### 📂 Project Structure

```text
.
├── internals/
│   ├── controllers/  # Auth, OAuth, 2FA, and User logic
│   ├── initializers/ # DB, Env, and Background Janitor
│   ├── middleware/   # JWT/MFA verification and Blacklist checking
│   ├── models/       # GORM schemas (User, Session, Blacklist)
│   └── utils/        # Crypto, Token generation, Emailing & helpers
├── main.go           # Application entry point
├── .air.toml         # Hot reload configuration
└── .env.example      # Environment variables example

```

---

### ⚙️ Getting Started

#### 1. Gmail SMTP Setup (Verification Emails)

To enable email verification, you must use a Google **App Password**. Google blocks standard password authentication for SMTP to protect your account.

- **Step 1: Identify your GMAIL_USER** This is your full Gmail address (e.g., nafees@gmail.com). This account will act as the system sender for all verification codes.

- **Step 2: Enable 2-Step Verification** Google requires 2FA to be active before allowing App Passwords.
   1. Go to your Google Security Settings.

   2. Under "**How you sign in to Google**," ensure **2-Step Verification** is turned **ON**.

- **Step 3: Generate the GMAIL_APP_PASSWORD**   
   1.  Navigate directly to the **App Passwords** page: 👉 **[Generate App Password Here](https://myaccount.google.com/apppasswords)**.

   2.  Note: If the link doesn't appear, search for "App Passwords" in the search bar at the top of your Google Account page.

   3.  **Select Other (Custom name)**, enter a name like Gin-Auth-App, and click **Create**.

   4.  **Copy the 16-character code**.

   ⚠️ **Critical**: Paste the code into your `.env` file. You will not be able to see this code again once the window is closed.


#### 2. Configuration

Create a `.env` file in the root directory:

```env
APP_NAME=your_app_name
PORT=3000
DB_URL=local.db

# JWT & Cleanup Configuration
JWT_SECRET_KEY=your_jwt_signing_secret
ACCESS_TOKEN_EXPIRATION_SECONDS=900
REFRESH_TOKEN_EXPIRATION_SECONDS=604800
CLEANUP_INTERVAL_MINUTES=30

ENCRYPTION_KEY=your_32_char_hex_key_for_2fa # openssl rand -hex 16

# Security Configuration
COOKIE_SECURE=false # Set to true for production/HTTPS
COOKIE_DOMAIN=

# Google OAuth2
GOOGLE_CLIENT_ID=your_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_secret
GOOGLE_REDIRECT_URL=http://localhost:3000/auth/google/callback

# Gmail SMTP
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

#### **Public Routes**

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/` | **Health Check**: System status and metadata. |
| `POST` | `/signup` | Creates account and triggers email verification. |
| `POST` | `/verify` | Validates email OTP and activates account. |
| `POST` | `/resend-code` | Requests a fresh verification code (1-min cooldown). |
| `POST` | `/login` | **Gateway**: Checks password. Returns mfa_required: true if 2FA is active. |
| `POST` | `/2fa/login-verify` | **MFA Step 2**: Validates Authenticator App code to finalize session. |

#### **Protected Routes (Requires JWT)**

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/logout` | Revokes DB session and blacklists JTI. |
| `GET` | `/validate` | Verifies current session and returns user data. |
| `POST` | `/2fa/setup` | Generates a new TOTP secret and QR code. |
| `POST` | `/2fa/activate` | Verifies initial TOTP code to enable MFA on account. |

#### **Auth Routes**

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/auth/refresh` | **Rotation**: Exchanges old refresh token for new pair. |
| `GET` | `/auth/google/login` | Redirects to Google Consent screen. |
| `GET` | `/auth/google/callback` | Finalizes Google OAuth2 authentication. |

---

### 🧹 Database Maintenance

The **Background Janitor** goroutine runs every `CLEANUP_INTERVAL_MINUTES` to ensure the database remains optimized:

1. **Session Purge:** Removes rows where `expires_at < now`.
2. **Blacklist Purge:** Cleans JTIs once the access token's lifespan is over.
3. **Ghost Account Cleanup:** Deletes users who haven't verified their email within 24 hours.


---

### 🔑 OAuth2 Setup Reference

For a step-by-step guide on how to configure your Google Cloud Console, refer to the:
👉 **[Google OAuth2 Setup Guide](./docs/GOOGLE_OAUTH_SETUP.md)**