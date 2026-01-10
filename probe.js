(function () {
  var probeInterval = null;
  var PROBE_INTERVAL_MS = 5000; // Send probes every 5 seconds

  async function runProbes() {
    try {
      await fetch("/ds/a", { method: "POST", keepalive: true, credentials: "include" });
      await fetch("/ds/b", { method: "POST", keepalive: true, credentials: "include" });
    } catch (e) {
      // Silent fail - don't break on network errors
    }
  }

  function startContinuousProbes() {
    // Run immediately on load
    runProbes();
    
    // Then run every interval
    if (probeInterval) clearInterval(probeInterval);
    probeInterval = setInterval(function() {
      runProbes();
    }, PROBE_INTERVAL_MS);
  }

  function showBanner(payload) {
    if (document.getElementById("ds-banner")) return;

    var div = document.createElement("div");
    div.id = "ds-banner";
    div.style.position = "fixed";
    div.style.left = "0";
    div.style.right = "0";
    div.style.top = "0";
    div.style.zIndex = "999999";
    div.style.padding = "12px 16px";
    div.style.fontFamily = "Arial, sans-serif";
    div.style.fontSize = "14px";
    div.style.background = "#111";
    div.style.color = "#fff";
    div.style.borderBottom = "2px solid #ff3b3b";

    var msg = "Interception detected (possible Burp Suite / proxy). This is a heuristic warning, not a final proof.";
    if (payload && payload.level) {
      msg += "  Level: " + payload.level.toUpperCase() + " | Score: " + payload.score;
    }
    div.textContent = msg;

    var close = document.createElement("span");
    close.textContent = "  [X]";
    close.style.cursor = "pointer";
    close.style.marginLeft = "10px";
    close.onclick = function () { div.remove(); };

    div.appendChild(close);
    document.body.appendChild(div);
  }

  async function checkStatus() {
    try {
      var r = await fetch("/api/session/status", { credentials: "include" });
      var j = await r.json();
      if (j.system_enabled && j.flagged) showBanner(j);
    } catch (e) {}
  }

  // Start continuous monitoring
  startContinuousProbes();
  
  // Check status periodically
  checkStatus();
  setInterval(checkStatus, 3000);
  
  // Cleanup on page unload
  if (window.addEventListener) {
    window.addEventListener("beforeunload", function() {
      if (probeInterval) clearInterval(probeInterval);
    });
  }
})();
