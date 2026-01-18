## Gin Auth & OAuth2 Project

This repository contains a robust, production-ready **Go (Gin)** authentication backend. It features standard email/password authentication, Google OAuth2 integration, and a sophisticated stateless logout system using JWT blacklisting with automated background cleanup.

---

### 🚀 Key Features

* **Secure Authentication:** Standard Signup/Login with password hashing.
* **Google OAuth2 Integration:** Seamless social login via Google.
* **JWT Management:** Stateless authentication using JSON Web Tokens with unique `jti` identifiers.
* **Hybrid Logout System:** A `Blacklist` table in SQLite stores revoked tokens until their natural expiration.
* **Automated Maintenance:** A background goroutine (janitor) that periodically purges expired blacklist entries to keep the database small.
* **Developer Experience:** Hot reloading configured with **Air** for rapid development.

---

### 🛠️ Tech Stack

* **Language:** Go (Golang)
* **Framework:** Gin Gonic
* **Database:** SQLite (via GORM)
* **Authentication:** JWT (v5), OAuth2
* **Hot Reload:** Air

---

### 📂 Project Structure

```text
.
├── internals/
│   ├── controllers/  # Auth, OAuth, and User logic
│   ├── initializers/ # DB connection, and Cleanup tasks
│   ├── middleware/   # JWT verification and Blacklist checking
│   ├── models/       # GORM schemas (User, Blacklist)
│   └── utils/        # Token generation & helper functions
├── main.go           # Application entry point
├── .air.toml         # Hot reload configuration
└── .env.example      # Environment variables example

```

---

### ⚙️ Getting Started

#### 1. Configuration

Create a `.env` file in the root directory and populate it with your credentials:

```env
PORT=3000
DB_URL=local.db
SECRET=your_jwt_signing_secret

# JWT & Cleanup Configuration
JWT_EXPIRATION_SECONDS=86400
CLEANUP_INTERVAL_MINUTES=30

# Google OAuth2 Credentials
GOOGLE_CLIENT_ID=your_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_client_secret
GOOGLE_REDIRECT_URL=http://localhost:3000/auth/google/callback
```

#### 2. Running the Project

For development with hot reloading:

```bash
air
```

For standard execution:

```bash
go run main.go
```

---

### 🧪 API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/signup` | Create a new user account |
| `POST` | `/login` | Authenticate and receive a JWT |
| `GET` | `/auth/google/login` | Redirect to Google for OAuth |
| `GET` | `/auth/google/callback` | Handle Google OAuth response |
| `POST` | `/logout` | Revoke current token (Blacklist) |
| `GET` | `/validate` | Check if session is valid (Protected) |

---

### 🧹 Database Maintenance

The project automatically manages the `Blacklist` table. It uses a **background goroutine** that wakes up every `CLEANUP_INTERVAL_MINUTES` to permanently delete records where `CreatedAt` is older than the `JWT_EXPIRATION_SECONDS`. This ensures your SQLite file does not grow indefinitely.

---

### 🔑 OAuth2 Setup Reference
For a step-by-step guide on how to configure your Google Cloud Console and retrieve your credentials, please refer to the:
👉 **[Google OAuth2 Setup Guide](./docs/GOOGLE_OAUTH_SETUP.md)**