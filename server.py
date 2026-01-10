import os
import time
import json
import secrets
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from functools import wraps

import requests
from flask import Flask, request, jsonify, make_response, send_from_directory, abort, session, render_template_string

import config

APP_DIR = os.path.dirname(os.path.abspath(__file__))
WEBSITE_DIR = os.path.join(APP_DIR, "Website")
LOG_DIR = os.path.join(APP_DIR, "logs")
LOG_PATH = os.path.join(LOG_DIR, "detections.jsonl")

os.makedirs(WEBSITE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# Admin panel HTML template
ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Admin Control Panel - Detection System</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; background:#0b0f14; color:#e8eef7; margin:0; padding:24px; }
    .container { max-width:1400px; margin:auto; }
    .card { background:#111823; border:1px solid #1e2a3a; border-radius:14px; padding:24px; margin-bottom:20px; }
    h1 { margin:0 0 10px 0; font-size:24px; font-weight:600; }
    h2 { margin:20px 0 12px 0; font-size:18px; font-weight:600; color:#8cc2ff; }
    h3 { margin:16px 0 8px 0; font-size:16px; font-weight:600; }
    p { color:#b8c3d6; line-height:1.6; margin:8px 0; }
    .row { display:flex; gap:12px; flex-wrap:wrap; margin-top:14px; align-items:center; }
    button { border:0; border-radius:8px; padding:10px 20px; cursor:pointer; font-weight:600; font-size:14px; transition:all 0.2s; }
    button:hover { transform:translateY(-1px); opacity:0.9; }
    button:disabled { opacity:0.5; cursor:not-allowed; }
    .btn-enable { background:#1a6dff; color:#fff; }
    .btn-disable { background:#ff3b3b; color:#fff; }
    .btn-logout { background:#444; color:#fff; }
    .muted { font-size:13px; color:#9bb0cc; }
    .login-box { max-width:400px; margin:100px auto; }
    .login-box input { width:100%; padding:12px; margin:8px 0; border:1px solid #1e2a3a; border-radius:8px; background:#0b0f14; color:#e8eef7; font-size:14px; }
    .login-box button { width:100%; margin-top:8px; }
    .status-badge { display:inline-block; padding:6px 12px; border-radius:6px; font-size:12px; font-weight:600; }
    .status-on { background:#1a6dff; color:#fff; }
    .status-off { background:#444; color:#ccc; }
    .detections-table { width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }
    .detections-table th, .detections-table td { padding:10px; text-align:left; border-bottom:1px solid #1e2a3a; }
    .detections-table th { background:#0b0f14; color:#8cc2ff; font-weight:600; }
    .detections-table tr:hover { background:#151a23; }
    .risk-high { color:#ff3b3b; font-weight:600; }
    .risk-warning { color:#ffa500; font-weight:600; }
    .risk-low { color:#9bb0cc; }
    .device-info { font-size:12px; color:#9bb0cc; }
    .ip-addr { font-family:monospace; color:#8cc2ff; }
    code { background:#0b0f14; padding:2px 6px; border-radius:6px; border:1px solid #1e2a3a; font-size:12px; }
    a { color:#8cc2ff; text-decoration:none; }
    a:hover { text-decoration:underline; }
    .error { color:#ff3b3b; margin-top:8px; }
    .success { color:#4caf50; margin-top:8px; }
    .refresh-info { font-size:12px; color:#666; margin-top:8px; }
  </style>
</head>
<body>
  <div class="container">
    <div id="loginPanel" class="login-box card" style="display:none;">
      <h1>Admin Login</h1>
      <p class="muted">Enter admin password to access the control panel.</p>
      <input type="password" id="passwordInput" placeholder="Admin password" autocomplete="current-password" />
      <button class="btn-enable" onclick="login()">Login</button>
      <div id="loginError" class="error"></div>
    </div>

    <div id="mainPanel" style="display:none;">
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
          <h1>Detection Control Panel</h1>
          <button class="btn-logout" onclick="logout()">Logout</button>
        </div>
        <p>
          This is a <b>lightweight heuristic security layer</b> that helps you <b>spot risk early</b>.
          It places a <b>flag</b> on sessions that show signs of connection interception (possible Burp Suite / proxy).
          <br><br>
          It is <b>NOT</b> final proof. Do <b>NOT</b> auto-ban users based on this alone.
        </p>

        <div class="row">
          <button class="btn-enable" onclick="enable()" id="enableBtn">Enable Detection</button>
          <button class="btn-disable" onclick="disable()" id="disableBtn">Disable Detection</button>
          <span id="systemStatus" class="status-badge status-off">OFF</span>
        </div>
        <p class="muted">System status will update automatically. All detections are logged to <code>logs/detections.jsonl</code></p>
      </div>

      <div class="card">
        <h2>Suspicious Users</h2>
        <p class="muted">Users with probe delay > 3 seconds (potential interception detected).</p>
        <div id="suspiciousContainer">
          <p class="muted">Loading suspicious users...</p>
        </div>
        <div class="refresh-info">Auto-refreshing every 5 seconds</div>
      </div>

      <div class="card">
        <h2>Recent Detections</h2>
        <p class="muted">Showing all interception detection events with user IP and device information.</p>
        <div id="detectionsContainer">
          <p class="muted">Loading detections...</p>
        </div>
        <div class="refresh-info">Auto-refreshing every 5 seconds</div>
      </div>

      <div class="card">
        <h2>Integration</h2>
        <p>Add this line to your website HTML pages:</p>
        <code>&lt;script src="/ds/probe.js"&gt;&lt;/script&gt;</code>
        <br><br>
        <p class="muted">Your website files are served from the <b>Website/</b> folder.</p>
        <p class="muted">Open website: <a href="/" target="_blank">/</a></p>
      </div>
    </div>
  </div>

<script>
let refreshInterval = null;

async function checkAuth() {
  try {
    const r = await fetch("/api/auth/status");
    const data = await r.json();
    if (data.authenticated) {
      document.getElementById("loginPanel").style.display = "none";
      document.getElementById("mainPanel").style.display = "block";
      refresh();
      if (!refreshInterval) {
        refreshInterval = setInterval(refresh, 5000);
      }
    } else {
      document.getElementById("loginPanel").style.display = "block";
      document.getElementById("mainPanel").style.display = "none";
      if (refreshInterval) {
        clearInterval(refreshInterval);
        refreshInterval = null;
      }
    }
  } catch (e) {
    console.error("Auth check failed", e);
  }
}

async function login() {
  const password = document.getElementById("passwordInput").value;
  const errorDiv = document.getElementById("loginError");
  errorDiv.textContent = "";
  
  try {
    const r = await fetch("/api/auth/login", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({password: password})
    });
    const data = await r.json();
    if (r.ok) {
      document.getElementById("passwordInput").value = "";
      await checkAuth();
    } else {
      errorDiv.textContent = data.error || "Login failed";
    }
  } catch (e) {
    errorDiv.textContent = "Network error. Please try again.";
  }
}

async function logout() {
  await fetch("/api/auth/logout", {method: "POST"});
  await checkAuth();
}

document.getElementById("passwordInput").addEventListener("keypress", function(e) {
  if (e.key === "Enter") login();
});

async function refresh() {
  try {
    const stateRes = await fetch("/api/system/state");
    if (stateRes.ok) {
      const state = await stateRes.json();
      const statusBadge = document.getElementById("systemStatus");
      if (state.system_enabled) {
        statusBadge.textContent = "ENABLED";
        statusBadge.className = "status-badge status-on";
      } else {
        statusBadge.textContent = "DISABLED";
        statusBadge.className = "status-badge status-off";
      }
    }
  } catch (e) {
    console.error("Failed to refresh state", e);
  }

  try {
    const detectionsRes = await fetch("/api/detections?limit=100");
    if (detectionsRes.ok) {
      const data = await detectionsRes.json();
      displayDetections(data.items || []);
    }
  } catch (e) {
    console.error("Failed to refresh detections", e);
  }

  try {
    const suspiciousRes = await fetch("/api/suspicious");
    if (suspiciousRes.ok) {
      const data = await suspiciousRes.json();
      displaySuspiciousUsers(data.users || []);
    }
  } catch (e) {
    console.error("Failed to refresh suspicious users", e);
  }
}

function displayDetections(items) {
  const container = document.getElementById("detectionsContainer");
  
  if (items.length === 0) {
    container.innerHTML = "<p class='muted'>No detections yet. Enable the system to start monitoring.</p>";
    return;
  }

  let html = `<table class="detections-table">
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>IP Address</th>
        <th>Device</th>
        <th>OS</th>
        <th>Browser</th>
        <th>Risk Level</th>
        <th>Score</th>
        <th>Gap (s)</th>
        <th>Session ID</th>
      </tr>
    </thead>
    <tbody>`;

  items.reverse().forEach(item => {
    const risk = item.risk || {};
    const deviceInfo = item.device_info || {device: "Unknown", os: "Unknown", browser: "Unknown"};
    const riskLevel = risk.level || "unknown";
    const riskClass = `risk-${riskLevel}`;
    
    html += `<tr>
      <td>${item.ts || "N/A"}</td>
      <td class="ip-addr">${item.ip || "N/A"}</td>
      <td>${deviceInfo.device || "Unknown"}</td>
      <td>${deviceInfo.os || "Unknown"}</td>
      <td>${deviceInfo.browser || "Unknown"}</td>
      <td class="${riskClass}">${riskLevel.toUpperCase()}</td>
      <td>${risk.score || 0}</td>
      <td>${risk.gap_seconds ? risk.gap_seconds.toFixed(2) : "N/A"}</td>
      <td style="font-family:monospace; font-size:11px;">${(item.sid || "").substring(0, 16)}...</td>
    </tr>`;
  });

  html += `</tbody></table>`;
  html += `<p class="muted" style="margin-top:12px;">Total: ${items.length} detection(s)</p>`;
  container.innerHTML = html;
}

function displaySuspiciousUsers(users) {
  const container = document.getElementById("suspiciousContainer");
  
  if (users.length === 0) {
    container.innerHTML = "<p class='muted'>No suspicious users detected yet. The system will flag users with probe delay > 3 seconds.</p>";
    return;
  }

  let html = `<table class="detections-table">
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Device</th>
        <th>OS</th>
        <th>Browser</th>
        <th>Gap (s)</th>
        <th>Detection Count</th>
        <th>First Detected</th>
        <th>Last Seen</th>
        <th>Session ID</th>
      </tr>
    </thead>
    <tbody>`;

  users.forEach(user => {
    const deviceInfo = user.device_info || {device: "Unknown", os: "Unknown", browser: "Unknown"};
    const gapSeconds = user.gap_seconds || 0;
    const gapClass = gapSeconds > 10 ? "risk-high" : gapSeconds > 3 ? "risk-warning" : "";
    
    html += `<tr>
      <td class="ip-addr">${user.ip || "N/A"}</td>
      <td>${deviceInfo.device || "Unknown"}</td>
      <td>${deviceInfo.os || "Unknown"}</td>
      <td>${deviceInfo.browser || "Unknown"}</td>
      <td class="${gapClass}" style="font-weight:600;">${gapSeconds.toFixed(2)}</td>
      <td>${user.detection_count || 1}</td>
      <td>${user.first_detected || "N/A"}</td>
      <td>${user.last_seen || "N/A"}</td>
      <td style="font-family:monospace; font-size:11px;">${(user.sid || "").substring(0, 16)}...</td>
    </tr>`;
  });

  html += `</tbody></table>`;
  html += `<p class="muted" style="margin-top:12px;">Total: ${users.length} suspicious user(s) - Probe delay > 3 seconds</p>`;
  container.innerHTML = html;
}

async function enable() {
  try {
    const r = await fetch("/api/system/enable", {method: "POST"});
    if (r.ok) {
      await refresh();
    } else {
      alert("Failed to enable system. Make sure you are logged in.");
      await checkAuth();
    }
  } catch (e) {
    alert("Network error. Please try again.");
  }
}

async function disable() {
  try {
    const r = await fetch("/api/system/disable", {method: "POST"});
    if (r.ok) {
      await refresh();
    } else {
      alert("Failed to disable system. Make sure you are logged in.");
      await checkAuth();
    }
  } catch (e) {
    alert("Network error. Please try again.");
  }
}

// Initialize
checkAuth();
</script>
</body>
</html>
"""

app = Flask(__name__)

# Session security
if config.FLASK_SECRET_KEY:
    app.secret_key = config.FLASK_SECRET_KEY
else:
    # Generate a secret key if not set
    app.secret_key = secrets.token_urlsafe(32)

def iso(ts: Optional[float] = None) -> str:
    ts = ts or time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts))

def get_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def get_ua() -> str:
    return (request.headers.get("User-Agent") or "unknown")[:300]

def parse_device_info(ua: str) -> Dict[str, str]:
    """Parse User-Agent to extract device, OS, and browser info."""
    device = "Unknown"
    os_name = "Unknown"
    browser = "Unknown"
    
    if not ua or ua == "unknown":
        return {"device": device, "os": os_name, "browser": browser}
    
    ua_lower = ua.lower()
    
    # Detect device type
    if any(x in ua_lower for x in ["mobile", "android", "iphone", "ipad", "ipod"]):
        if "tablet" in ua_lower or "ipad" in ua_lower:
            device = "Tablet"
        elif any(x in ua_lower for x in ["iphone", "ipod"]):
            device = "Mobile (iOS)"
        elif "android" in ua_lower:
            device = "Mobile (Android)"
        else:
            device = "Mobile"
    else:
        device = "Desktop"
    
    # Detect OS
    if "windows" in ua_lower:
        if "windows nt 10.0" in ua_lower or "windows 10" in ua_lower:
            os_name = "Windows 10/11"
        elif "windows nt 6.3" in ua_lower:
            os_name = "Windows 8.1"
        elif "windows nt 6.2" in ua_lower:
            os_name = "Windows 8"
        elif "windows nt 6.1" in ua_lower:
            os_name = "Windows 7"
        else:
            os_name = "Windows"
    elif "mac os x" in ua_lower or "macintosh" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    elif "android" in ua_lower:
        os_match = re.search(r"android\s+([\d.]+)", ua_lower)
        os_name = f"Android {os_match.group(1)}" if os_match else "Android"
    elif "iphone os" in ua_lower or "ios" in ua_lower:
        ios_match = re.search(r"os\s+([\d_]+)", ua_lower)
        os_name = f"iOS {ios_match.group(1).replace('_', '.')}" if ios_match else "iOS"
    
    # Detect browser
    if "chrome" in ua_lower and "edg" not in ua_lower:
        chrome_match = re.search(r"chrome/([\d.]+)", ua_lower)
        browser = f"Chrome {chrome_match.group(1).split('.')[0]}" if chrome_match else "Chrome"
    elif "firefox" in ua_lower:
        ff_match = re.search(r"firefox/([\d.]+)", ua_lower)
        browser = f"Firefox {ff_match.group(1).split('.')[0]}" if ff_match else "Firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser = "Safari"
    elif "edg" in ua_lower:
        edge_match = re.search(r"edg/([\d.]+)", ua_lower)
        browser = f"Edge {edge_match.group(1).split('.')[0]}" if edge_match else "Edge"
    elif "opera" in ua_lower or "opr" in ua_lower:
        browser = "Opera"
    
    return {"device": device, "os": os_name, "browser": browser}

def get_session_id(resp=None) -> str:
    sid = request.cookies.get("dsid")
    if sid:
        return sid
    sid = secrets.token_urlsafe(16)
    if resp is not None:
        resp.set_cookie("dsid", sid, max_age=60*60*24*30, samesite="Lax")
    return sid

def append_log(obj: dict) -> None:
    line = json.dumps(obj, ensure_ascii=False)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def tail_log(limit: int = 200) -> List[dict]:
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()[-limit:]
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln:
            continue
        try:
            out.append(json.loads(ln))
        except Exception:
            continue
    return out



def send_discord_webhook(message: str) -> None:
    url = getattr(config, "DISCORD_WEBHOOK_URL", "") or ""
    if not url:
        print("[WEBHOOK] URL empty")
        return
    try:
        r = requests.post(url, json={"content": message}, timeout=6)
        print("[WEBHOOK] status:", r.status_code, "body:", r.text[:200])
        r.raise_for_status()
    except Exception as e:
        print("[WEBHOOK] error:", repr(e))



@dataclass
class ProbeEvent:
    ts: float
    ep: str

@dataclass
class Risk:
    score: int
    level: str  # low / warning / high
    gap_seconds: Optional[float]
    reasons: List[str]
    first_flag_iso: str

STATE: Dict[str, Dict] = {}
SYSTEM_ENABLED = False  # default OFF
SUSPICIOUS_USERS: Dict[str, Dict] = {}  # Track suspicious users with device info

def require_auth(f):
    """Decorator to require admin authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("authenticated"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def prune_events(events: List[ProbeEvent], now: float) -> List[ProbeEvent]:
    cutoff = now - float(config.EVENT_WINDOW_SECONDS)
    return [e for e in events if e.ts >= cutoff]

def evaluate(sid: str, ip: str, ua: str) -> Optional[Risk]:
    data = STATE.get(sid)
    if not data:
        return None
    events: List[ProbeEvent] = data.get("events", [])
    if len(events) < 2:
        return None

    last_a = None
    last_b = None
    for e in reversed(events):
        if last_b is None and e.ep.endswith("/ds/b"):
            last_b = e
            continue
        if last_b is not None and e.ep.endswith("/ds/a"):
            last_a = e
            break
    if not (last_a and last_b):
        return None

    gap = max(0.0, last_b.ts - last_a.ts)
    
    # Check if gap exceeds suspicious threshold (3 seconds)
    suspicious_threshold = float(config.SUSPICIOUS_GAP_SECONDS)
    if gap > suspicious_threshold:
        # Add to suspicious users list with device info
        device_info = parse_device_info(ua)
        SUSPICIOUS_USERS[sid] = {
            "sid": sid,
            "ip": ip,
            "ua": ua,
            "device_info": device_info,
            "gap_seconds": gap,
            "last_seen": iso(time.time()),
            "first_detected": SUSPICIOUS_USERS.get(sid, {}).get("first_detected", iso(time.time())),
            "detection_count": SUSPICIOUS_USERS.get(sid, {}).get("detection_count", 0) + 1
        }
    
    score = 0
    reasons: List[str] = []

    if gap >= float(config.HIGH_GAP_SECONDS):
        score += 70
        reasons.append(f"Large probe delay ({gap:.2f}s) suggests possible interception/manual hold.")
    elif gap >= float(config.WARN_GAP_SECONDS):
        score += 40
        reasons.append(f"Noticeable probe delay ({gap:.2f}s) is unusual for normal browsing.")
    elif gap > suspicious_threshold:
        score += 30
        reasons.append(f"Suspicious probe delay ({gap:.2f}s) detected - added to suspicious list.")
    else:
        score += 5
        reasons.append(f"Probe pair seen with normal delay ({gap:.2f}s).")

    now_ts = events[-1].ts
    recent = [e for e in events if e.ts >= (now_ts - float(config.RETRY_WINDOW_SECONDS))]
    a_count = sum(1 for e in recent if e.ep.endswith("/ds/a"))
    b_count = sum(1 for e in recent if e.ep.endswith("/ds/b"))
    if a_count > 1 or b_count > 1:
        score += 15
        reasons.append("Repeated probe hits detected (retries/automation).")

    score = max(0, min(100, score))
    level = "high" if score >= 80 else "warning" if score >= 50 else "low"
    existing = data.get("risk")
    first_flag = existing.first_flag_iso if existing is not None else iso(now_ts)
    return Risk(score=score, level=level, gap_seconds=gap, reasons=reasons, first_flag_iso=first_flag)

@app.post("/api/auth/login")
def api_login():
    """Admin login endpoint."""
    data = request.get_json() or {}
    password = data.get("password", "")
    
    # Simple password check (you can enhance this with hashing)
    if password == config.ADMIN_PASSWORD:
        session["authenticated"] = True
        return jsonify({"ok": True, "message": "Login successful"})
    return jsonify({"error": "Invalid password"}), 401

@app.post("/api/auth/logout")
def api_logout():
    """Admin logout endpoint."""
    session.pop("authenticated", None)
    return jsonify({"ok": True, "message": "Logged out"})

@app.get("/api/auth/status")
def api_auth_status():
    """Check authentication status."""
    return jsonify({"authenticated": session.get("authenticated", False)})

@app.get("/api/health")
def api_health():
    return jsonify({"status": "ok", "system_enabled": SYSTEM_ENABLED})

@app.post("/api/system/enable")
@require_auth
def api_enable():
    global SYSTEM_ENABLED
    SYSTEM_ENABLED = True
    return jsonify({"ok": True, "system_enabled": SYSTEM_ENABLED})

@app.post("/api/system/disable")
@require_auth
def api_disable():
    global SYSTEM_ENABLED
    SYSTEM_ENABLED = False
    return jsonify({"ok": True, "system_enabled": SYSTEM_ENABLED})

@app.get("/api/system/state")
@require_auth
def api_state():
    return jsonify({"system_enabled": SYSTEM_ENABLED})

@app.get("/api/detections")
@require_auth
def api_detections():
    """Get detection logs with enhanced device info."""
    limit = int(request.args.get("limit", "200"))
    limit = max(1, min(2000, limit))
    items = tail_log(limit)
    
    # Enhance items with device info
    enhanced_items = []
    for item in items:
        ua = item.get("ua", "unknown")
        device_info = parse_device_info(ua)
        enhanced_item = {
            **item,
            "device_info": device_info
        }
        enhanced_items.append(enhanced_item)
    
    return jsonify({"count": len(enhanced_items), "items": enhanced_items})

@app.get("/api/suspicious")
@require_auth
def api_suspicious():
    """Get list of suspicious users (gap > 3 seconds)."""
    # Convert dict to list and sort by last_seen (newest first)
    suspicious_list = list(SUSPICIOUS_USERS.values())
    suspicious_list.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
    return jsonify({"count": len(suspicious_list), "users": suspicious_list})

@app.get("/api/session/status")
def api_session_status():
    sid = request.cookies.get("dsid")
    if not sid or sid not in STATE or not STATE[sid].get("risk"):
        return jsonify({"flagged": False, "system_enabled": SYSTEM_ENABLED})
    risk: Risk = STATE[sid]["risk"]
    flagged = risk.level in ("warning", "high")
    return jsonify({
        "flagged": flagged,
        "level": risk.level,
        "score": risk.score,
        "reasons": risk.reasons,
        "first_flag_iso": risk.first_flag_iso,
        "system_enabled": SYSTEM_ENABLED
    })

@app.post("/ds/a")
def probe_a():
    return _handle_probe("/ds/a")

@app.post("/ds/b")
def probe_b():
    return _handle_probe("/ds/b")

def _handle_probe(endpoint: str):
    resp = make_response(jsonify({"ok": True}))
    sid = get_session_id(resp)
    ip = get_ip()
    ua = get_ua()

    if not SYSTEM_ENABLED:
        return resp

    now = time.time()
    data = STATE.get(sid) or {"ip": ip, "ua": ua, "events": [], "risk": None}
    STATE[sid] = data

    data["ip"] = ip
    data["ua"] = ua
    data["events"].append(ProbeEvent(ts=now, ep=endpoint))
    data["events"] = prune_events(data["events"], now)

    risk = evaluate(sid, ip, ua)
    if risk:
        data["risk"] = risk
        # Log if suspicious (gap > 3) or if risk level is warning/high
        if (risk.gap_seconds and risk.gap_seconds > float(config.SUSPICIOUS_GAP_SECONDS)) or risk.level in ("warning", "high"):
            device_info = parse_device_info(ua)
            record = {
                "ts": iso(now),
                "sid": sid,
                "ip": ip,
                "ua": ua,
                "device_info": device_info,
                "endpoint": endpoint,
                "risk": asdict(risk),
                "note": "Heuristic indicator only. Not a final proof. Do NOT auto-ban based on this alone."
            }
            append_log(record)
            device_str = f"{device_info['device']} | {device_info['os']} | {device_info['browser']}"
            send_discord_webhook(
                f"⚠️ Interception risk flagged ({risk.level.upper()} | score={risk.score}) | IP={ip} | Device={device_str} | gap={risk.gap_seconds:.2f}s"
            )
    return resp

@app.get("/")
def serve_index():
    index_path = os.path.join(WEBSITE_DIR, "index.html")
    if not os.path.exists(index_path):
        return jsonify({
            "message": "No Website/index.html found. Put your website inside the 'Website' folder.",
            "hint": "Open /control to enable/disable the system."
        })
    return send_from_directory(WEBSITE_DIR, "index.html")

@app.get("/control")
def serve_control():
    """Protected admin control panel."""
    return render_template_string(ADMIN_TEMPLATE)

@app.get("/ds/probe.js")
def serve_probe_js():
    return send_from_directory(APP_DIR, "probe.js")

@app.get("/<path:filename>")
def serve_any(filename: str):
    safe_path = os.path.abspath(os.path.join(WEBSITE_DIR, filename))
    if not safe_path.startswith(os.path.abspath(WEBSITE_DIR) + os.sep):
        abort(404)
    if not os.path.exists(safe_path):
        abort(404)
    return send_from_directory(WEBSITE_DIR, filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
