# Burp / Proxy Interception Detection (Heuristic Layer)

Lightweight Burp/Proxy Detection System based on request behavior, timing patterns, and endpoint probes.

This project is a **lightweight security layer** that helps you **spot risk early**.
It places a **flag** on sessions that show behavioral signs of **connection interception**
(e.g., possible Burp Suite / proxy usage).

**Important**: This is a heuristic indicator only.
Do **NOT** treat it as final proof and do **NOT** auto-ban users based on it.

## Features

- 🔒 **Protected Admin Panel**: Password-authenticated control panel
- 🔄 **Continuous Monitoring**: Probe requests sent continuously every 5 seconds for real-time detection
- 📊 **Suspicious Users List**: Automatic tracking of users with probe delay > 3 seconds
- 📈 **Enhanced Detection Display**: Shows IP address, device type, OS, and browser for each detection
- 🔍 **Real-time Monitoring**: View all detection events and suspicious users in detailed admin dashboard
- 📝 **Comprehensive Logging**: All detections logged to `logs/detections.jsonl`
- 🔔 **Optional Discord Notifications**: Get notified via Discord webhook (disabled by default)
- 🚀 **Easy Integration**: Just add one script tag to your website

## What you get

- A Flask server that:
  - Serves your website from the `Website/` folder (all file types)
  - Probe endpoints: `POST /ds/a` and `POST /ds/b`
  - Password-protected admin control panel at `/control`
  - Logs risk events with device intelligence to `logs/detections.jsonl`
  - Optional Discord webhook notification (disabled by default)
- A demo website (`Website/index.html`)
- Protected admin control panel with authentication

## Quick Start

### Windows
```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python server.py
```

### Linux/Mac
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python server.py
```

### First Time Setup

1. **Configure Admin Password** (REQUIRED):
   Edit `config.py` and change the default password:
   ```python
   ADMIN_PASSWORD = "your-strong-password-here"  # Change this!
   ```
   
   

2. Open your browser:
   - Website: http://localhost:5000/
   - Admin Panel: http://localhost:5000/control

3. **Login to Admin Panel**:
   - Enter the password you set in `config.py`
   - Click "Enable Detection" to start monitoring
   - View all detections in real-time with user IP and device information

## Integrate with ANY website

1. Put your website files inside the `Website/` folder
2. Add this line to your HTML pages (usually before `</body>`):
   ```html
   <script src="/ds/probe.js"></script>
   ```
   That's it! The detection system will automatically monitor visitors.

## Admin Panel Features

The protected admin panel at `/control` provides:

- **System Control**: Enable/disable the detection system
- **Suspicious Users List**: Real-time list of all users with probe delay > 3 seconds, showing:
  - IP address
  - Device information (type, OS, browser)
  - Probe gap time
  - Detection count (how many times flagged)
  - First detected and last seen timestamps
  - Session ID
- **Detection Dashboard**: View all detection events in a detailed table showing:
  - Timestamp of detection
  - User IP address
  - Device type (Desktop/Mobile/Tablet)
  - Operating System (Windows, macOS, Linux, Android, iOS)
  - Browser (Chrome, Firefox, Safari, Edge, etc.)
  - Risk level (HIGH/WARNING/LOW)
  - Detection score (0-100)
  - Probe timing gap
  - Session ID for tracking

## Configuration

Edit `config.py` to customize:

```python

ADMIN_PASSWORD = "admin123"  # Change this to a strong password!

# Detection thresholds
SUSPICIOUS_GAP_SECONDS = 3  # Suspicious threshold - users added to list if gap > this (seconds)
WARN_GAP_SECONDS = 3.0        # Warning threshold (seconds)
HIGH_GAP_SECONDS = 10.0       # High risk threshold (seconds)
EVENT_WINDOW_SECONDS = 60.0   # How long to keep probe events (seconds)
RETRY_WINDOW_SECONDS = 10.0   # Window for detecting retries (seconds)

# Optional Discord notifications
DISCORD_WEBHOOK_URL = ""  # Empty = disabled
```

## Discord Webhook (Optional)

To enable Discord notifications, edit `config.py`:

```python
DISCORD_WEBHOOK_URL = ""
```

Notifications include:
- Risk level and score
- User IP address
- Device information
- Probe delay timing

## Security Notes

- ✅ Admin panel is password-protected
- ✅ All admin API endpoints require authentication
- ✅ Detection system is **disabled by default** (enable via admin panel)
- ✅ Session-based authentication prevents unauthorized access
- ⚠️ **Change the default password** in `config.py` before deploying to production!
- ⚠️ Use HTTPS in production for secure password transmission

## How It Works

The system uses continuous behavioral analysis:

1. **Continuous Probing**: Sends probe pairs (A then B) continuously every 5 seconds throughout the user session
2. **Delay Detection**: Measures time gap between probes - any gap > 3 seconds adds user to suspicious list
3. **Suspicious Tracking**: Users with probe delay > 3s are automatically tracked with device info
4. **Retry Detection**: Monitors for repeated probe requests within time windows
5. **Risk Scoring**: Calculates a risk score (0-100) based on detected patterns
6. **User Notification**: Shows a banner to flagged users (if system is enabled and risk level is warning/high)
7. **Admin Monitoring**: Real-time display of suspicious users and all detection events with full device intelligence
