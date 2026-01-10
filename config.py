"""
Configuration for the Burp/Proxy Interception Heuristic Layer.

Security:
- Set a strong ADMIN_PASSWORD to protect the control panel.
- Leave DISCORD_WEBHOOK_URL empty to disable Discord notifications.

Tip:
- If you want to hard-disable Discord feature, keep the commented line as-is.
"""

# Admin authentication password (REQUIRED - change this!)
ADMIN_PASSWORD = "admin123"  # Change this to a strong password!

# Flask secret key for session security (auto-generated if not set)
FLASK_SECRET_KEY = None  # Will auto-generate on first run

# DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/....."  # <-- remove the leading # to enable
DISCORD_WEBHOOK_URL = ""  # empty = disabled

# Detection thresholds
SUSPICIOUS_GAP_SECONDS = 3.0  # Flag as suspicious if gap > 3 seconds
WARN_GAP_SECONDS = 3.0        # Warning threshold
HIGH_GAP_SECONDS = 10.0       # High risk threshold

# How long we keep probe events per session (seconds)
EVENT_WINDOW_SECONDS = 60.0

# Duplicate probe hits within this window add mild suspicion (seconds)
RETRY_WINDOW_SECONDS = 10.0
