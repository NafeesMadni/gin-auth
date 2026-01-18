## 🛠️ Google Cloud Console Setup Instructions

To get your `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, follow these exact steps:

### 1. Project Initialization

* Go to the [Google Cloud Console](https://console.cloud.google.com/).
* Click the project dropdown in the top left and select **New Project**.
* Give it a name (e.g., "Gin-Auth-Backend") and click **Create**.

### 2. Configure the OAuth Consent Screen

* In the sidebar, navigate to **APIs & Services > OAuth consent screen**.
* **Critical Step**: If you see the message "Google Auth Platform not configured yet," click the Get Started button to begin.

* **App Information**: Fill in the "App name" and select your email for "User support email".

* **Audience**: Select External so anyone with a Google account can test it, then click Next.

* **Contact Information**: Enter your email address again for developer notifications.

* **Finish**: Review the terms, select I agree, and click Create.

### 3. Create OAuth 2.0 Credentials

* Go to **APIs & Services >  OAuth consent screen > Clients**.
* Click **+ Create client** at the top and select **OAuth client ID**.
* **Application type:** Select **Web application**.
* **Name:** Give it a descriptive name (e.g., "Development Web Client").
* **Authorized redirect URIs:** Click **+ Add URI** and enter:
`http://localhost:3000/auth/google/callback`
* Click **Create**.

### 4. Retrieve Your Secret Key

* A "OAuth client created" window will appear.
* If it only shows the Client ID, look at the sidebar under **Auth Platform** and click **Clients**.
* Click on your specific Client Name to open its settings.
* Locate the **Client Secret** on the right-hand side or download the configuration by clicking **Download JSON**.