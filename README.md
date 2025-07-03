# V2Ray Account Checker API (PHP) on Serv00.com

This guide will walk you through deploying the V2Ray Account Checker PHP API on [Serv00.com](https://serv00.com/) hosting. This API allows you to check the status, traffic usage, and expiry of V2Ray accounts from multiple X-UI panels by simply providing a V2Ray link, UUID, or email.

### Features

* **Multi-panel Support:** Connects to multiple X-UI V2Ray panels.
* **All Protocol Types:** Supports VMess, VLESS, Trojan, and Shadowsocks links/UUIDs.
* **Traffic Monitoring:** Displays upload, download, total, used, and remaining traffic.
* **Expiry Tracking:** Shows account expiry date and remaining time.
* **Clear JSON Output:** Provides well-structured and human-readable JSON responses.

### Prerequisites

* A Serv00.com hosting account.
* Basic understanding of SSH and FTP/SFTP.
* Your V2Ray X-UI panel URLs, usernames, and passwords.

---

### Step-by-Step Deployment

#### 1. Prepare Your `api.php` File

First, ensure your `api.php` file is correctly configured with your V2Ray panel details.

1.  Open the `api.php` file in a text editor.
2.  Locate the `$PANELS` array:

    ```php
    $PANELS = [
        'VIP Singapore 🇸🇬 Server(1)' => [
            'url' => '[http://34.53.21.67:123456/w0MW874U8fevz8D/](http://34.53.21.67:123456/w0MW874U8fevz8D/)',
            'username' => 'admin',
            'password' => 'admin'
        ],
        // ... other panels
    ];
    ```

3.  **Update this array** with your actual X-UI panel URLs, usernames, and passwords. Make sure the `url` includes the correct port and path if any (e.g., `/w0MW874U8fevz8D/`).

#### 2. Connect to Serv00 via SSH

You'll need to use SSH to enable `curl` for your PHP environment on Serv00.

1.  Log in to your Serv00.com account.
2.  Go to the **SSH access** section to find your SSH login details (username, host, port).
3.  Use an SSH client (like PuTTY on Windows, or your terminal on Linux/macOS) to connect:
    ```bash
    ssh your_serv00_username@your_serv00_host -p your_serv00_ssh_port
    ```
    Replace placeholders with your actual details.

#### 3. Enable `curl` for PHP

On Serv00, PHP extensions often need to be explicitly enabled for your user.

1.  Once connected via SSH, run the following command to enable the `curl` extension for your PHP 8.2 environment (assuming you are using PHP 8.2, which is common):
    ```bash
    php82-pecl install curl
    ```
    (If you are using a different PHP version, adjust `php82-pecl` accordingly, e.g., `php81-pecl`).
2.  Confirm the installation.

#### 4. Upload `api.php` to Serv00

Now, transfer your `api.php` file to your Serv00 web directory.

1.  Connect to your Serv00 account using an FTP/SFTP client (like FileZilla).
2.  Navigate to your public web directory, usually `domains/your_domain.com/public_html/`.
3.  Upload the `api.php` file to this directory. You can also create a subdirectory (e.g., `api/`) and upload it there: `domains/your_domain.com/public_html/api/api.php`.

---

#### 5. Test Your API

Once uploaded, you can test your API by accessing it via your web browser or a tool like Postman/Insomnia.

**Using GET Request:**

Open your web browser and go to:
`http://your_domain.com/api.php?config=YOUR_V2RAY_KEY_OR_LINK`

Replace `your_domain.com` with your actual domain, and `YOUR_V2RAY_KEY_OR_LINK` with a VMess link, VLESS link, Trojan link, Shadowsocks link, raw UUID, or an email address associated with an account on your panels.

**Example GET Request:**
