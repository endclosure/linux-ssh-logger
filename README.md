# SSH Discord notifier

The notifier reads OpenSSH authentication logs and sends connection, disconnection, failed-login, and new-file alerts to the webhooks in `config.json`. Alerts include the SSH username, client IP when available, source port on connection, and uploaded file basename. They do not include passwords, keys, raw log lines, or the VPS IP.

Run with Python 3 using `python3 main.py` before making the SSH connection you want to observe. It follows new log entries and does not replay earlier connections. It reads the configured `auth_log`, then `/var/log/secure`, then falls back to `journalctl`. The process needs permission to read the authentication log and outbound HTTPS access. Startup prints which log source it is following to stderr.

SSH login events include the connecting client's IP. Disconnection records include the IP when OpenSSH provides it; generic PAM close records include an IP only when that user has one unambiguous active client. File polling detects newly appearing files but cannot prove which SSH session uploaded them. Files already present when the service starts are not reported.
