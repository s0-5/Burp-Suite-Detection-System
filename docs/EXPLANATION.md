# Explanation (Concept & Features)

## Goal
Help you detect risk early by highlighting sessions that may be intercepting traffic.
This increases awareness and investigation scope.

## Why it is NOT a final proof
A server cannot prove Burp Suite usage. This system only uses heuristic signals.
Do **NOT** auto-ban users based on these indicators alone.

## Detection Signals
The system monitors behavioral patterns through **continuous probing**:

1. **Continuous Probe Monitoring**
   - Sends probe pairs (`/ds/a` then `/ds/b`) continuously every 5 seconds
   - Continuously monitors user behavior throughout their session
   - Allows for real-time detection of interception attempts

2. **Probe Delay Analysis**
   - Measures the time gap between probe A and probe B
   - **Suspicious threshold (> 3s)**: Users are added to suspicious list immediately
   - Large delays (>10s) suggest manual interception/manual hold
   - Medium delays (>3s) are flagged as warnings

3. **Retry Detection**
   - Monitors duplicate probe hits within a short window
   - Repeated requests may indicate automation or retry behavior
   - Adds additional risk score

## User-Facing Message
If a session is flagged, the website automatically shows a banner:
"Interception detected (possible Burp Suite / proxy). This is a heuristic warning, not a final proof."

The banner includes the risk level (HIGH/WARNING) and detection score.

## Admin Control Panel

### Authentication
The admin panel at `/control` is **password-protected** for security.
- Default password is set in `config.py` as `ADMIN_PASSWORD`
- **IMPORTANT**: Change the default password before deploying!
- All admin API endpoints require authentication

### Features
- **System Control**: Enable/Disable detection system
- **Suspicious Users List**: Real-time list of users with probe delay > 3 seconds
  - Shows IP address, device info, gap time, detection count
  - Tracks first detected and last seen timestamps
- **Detection Logs**: View all detection events in a detailed table
- **Device Intelligence**: Each detection shows:
  - IP Address of the user
  - Device type (Desktop/Mobile/Tablet)
  - Operating System (Windows, macOS, Linux, Android, iOS)
  - Browser (Chrome, Firefox, Safari, Edge, etc.)
  - Risk level and score
  - Time gap between probes
  - Session ID for tracking

### Detection Logging
All flagged sessions are logged to `logs/detections.jsonl` in JSONL format for analysis.
The log includes:
- Timestamp
- Session ID
- IP Address
- Full User-Agent string
- Parsed device information
- Risk assessment details (score, level, reasons)
- Probe timing data

### Discord Notifications (Optional)
You can optionally enable Discord webhook notifications by setting `DISCORD_WEBHOOK_URL` in `config.py`.
Notifications include:
- Risk level and score
- User IP address
- Device information
- Probe delay timing

## Configuration
All settings are in `config.py`:
- `ADMIN_PASSWORD`: Admin panel password (REQUIRED - change this!)
- `SUSPICIOUS_GAP_SECONDS`: Suspicious threshold - users with gap > this are added to suspicious list (default: 3s)
- `WARN_GAP_SECONDS`: Warning threshold for probe delay (default: 3.0s)
- `HIGH_GAP_SECONDS`: High risk threshold for probe delay (default: 10.0s)
- `EVENT_WINDOW_SECONDS`: How long to keep probe events per session (default: 60s)
- `RETRY_WINDOW_SECONDS`: Window for detecting retry behavior (default: 10s)
- `DISCORD_WEBHOOK_URL`: Optional Discord webhook for notifications

## Continuous Monitoring
The system now uses **continuous probing** instead of one-time checks:
- Probe pairs (A then B) are sent every 5 seconds
- This allows for continuous monitoring throughout the user session
- Any probe pair with delay > 3 seconds immediately adds the user to the suspicious list
- The suspicious list is maintained in memory and displayed in real-time in the admin panel

## Security Notes
- The control panel requires password authentication
- Session-based authentication prevents unauthorized access
- All admin API endpoints are protected with `@require_auth` decorator
- Detection system is disabled by default for safety
- Logs are stored locally and never transmitted unless Discord webhook is configured
