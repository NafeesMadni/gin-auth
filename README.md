## Gin Auth & OAuth2 Project

This repository contains a robust, production-ready **Go (Gin)** authentication backend. It features a modern **struct-based controller architecture** for scalable dependency management, standard email/password authentication, Google OAuth2 integration, and sophisticated session management.

---

### 🚀 Key Features

* **Modular Architecture:** Utilizes **Dependency Injection** to manage database connections, SMTP configurations, and security secrets across decoupled controller structs.
* **Session-Bound Security:** Implements **Signup/Login Session locking** via path-restricted cookies to prevent verification hijacking and race-condition exploits.
* **Passwordless Email OTP:** Supports a "Magic Code" login flow that allows users to authenticate via email without a password.
* **Multi-Factor Authentication (2FA):** Secure TOTP (Time-based One-Time Password) implementation with AES-256-GCM encryption for secrets at rest.
* **Path-Restricted Cookies:** Enhances security by restricting sensitive tokens (Refresh, Signup, and Login Sessions) to specific API paths to minimize cross-endpoint leakage.
* **Two-Step Secure Login:** Enhanced `/login` flow that detects MFA status and requires a secondary verification step via `/2fa/login-verify` before issuing session cookies.
* **Email Verification:** Integration with Gmail SMTP to verify accounts via OTP with intelligent **Upsert-aware** signup logic for expired codes.
* **Google OAuth2:** Seamless social login integration handled via a dedicated controller.
* **Refresh Token Rotation:** High-security session management that rotates tokens on every refresh to prevent replay attacks.
* **Hybrid Logout:** Supports stateful session revocation and stateless JTI blacklisting.
* **Automated Maintenance:** Background "janitor" goroutine to purge expired sessions, blacklist entries, login challenges, and abandoned unverified accounts.

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
│   ├── config/       # Low-Level shared configuration (CookieConfig, Env helpers)
│   ├── controllers/  # Struct-based handlers (Auth, MFA, Google, Token, Verification)
│   ├── initializers/ # DB initialization, load Env, and Background Janitor service
│   ├── middleware/   # JWT/MFA verification and Blacklist checking
│   ├── models/       # GORM schemas (User, Session, Blacklist, LoginChallenge)
│   └── utils/        # TokenManager, Crypto, and Email logic
├── main.go           # Application entry point
└── .env              # Environment configuration 

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

   1. **Rename the file**: Find `.env.example` in your root directory and rename it to `.env`.
   2. **Generate Secrets**: Use a secure method to generate your `JWT_SECRET_KEY` and `ENCRYPTION_KEY` (e.g., `openssl rand -hex 32`).
   3. **Set Cookie Paths**: Ensure the paths match your new **nested routing structure** to maintain session isolation.

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

Managed by `AuthController`, `VerificationController`, and `MFAController`.

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/` | **Health Check**: System status and metadata. |
| `POST` | `/signup` | **Upsert-aware**: Creates/Updates unverified accounts & sets Signup cookie. |
| `POST` | `/signup/otp/verify` | Validates email OTP against the `SignupID` session. |
| `POST` | `/signup/otp/resend` | Requests new code for the **active** signup session (1-min cooldown). |
| `POST` | `/request-login-otp` | Initiates Passwordless Login; creates a `LoginChallenge` record. |
| `POST` | `/login/otp/verify` | Validates Login OTP. |
| `POST` | `/login/otp/resend` | Refreshes the OTP and browser cookie for the active login session. |
| `POST` | `/login` | Password login. Returns `mfa_required` if 2FA is active. |
| `POST` | `/2fa/login-verify` | Validates Authenticator App code to finalize the session.  |

#### **Protected Routes (Requires JWT)**

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/logout` | Revokes DB session, clears cookies, and blacklists JTI. |
| `GET` | `/validate` | Verifies current session and returns user data. |
| `POST` | `/2fa/setup` | Generates a new TOTP secret and QR code. |
| `POST` | `/2fa/activate` | Verifies initial TOTP code to enable MFA on account. |

#### **Auth Routes**

Managed by `GoogleAuthController` and `TokenController`.

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/auth/refresh` | **Rotation**: Exchanges old refresh token for new pair via `TokenManager`. |
| `GET` | `/auth/google/login` | Redirects to Google Consent screen. |
| `GET` | `/auth/google/callback` | Finalizes Google OAuth2 authentication. |

---

### 🧹 Database Maintenance

The **Background Janitor** goroutine runs every `CLEANUP_INTERVAL_MINUTES` to ensure the database remains optimized:

1. **Login Challenges:** Purges abandoned OTP attempts where `session_expire_at < now`.
2. **Sessions & Blacklist:** Cleans up expired JWT sessions and JTI entries.
3. **Ghost Accounts:** Deletes users who haven't verified signup within 24 hours.


---

### 🔑 OAuth2 Setup Reference

For a step-by-step guide on how to configure your Google Cloud Console, refer to the:
👉 **[Google OAuth2 Setup Guide](./docs/GOOGLE_OAUTH_SETUP.md)**