/* ================================================================
   WebRTC Phone for FreeSWITCH – JsSIP-based SIP User Agent
   ================================================================ */

"use strict";

/* ---------- DOM references ---------- */
const $  = (id) => document.getElementById(id);

const ui = {
  wsUrl:         $("ws-url"),
  sipDomain:     $("sip-domain"),
  sipUser:       $("sip-user"),
  sipPass:       $("sip-pass"),
  displayName:   $("display-name"),
  iceStun:       $("ice-stun"),
  stunUrl:       $("stun-url"),
  btnConnect:    $("btn-connect"),
  btnDisconnect: $("btn-disconnect"),
  regIndicator:  $("reg-indicator"),
  regStatus:     $("reg-status"),
  dialInput:     $("dial-input"),
  callInfo:      $("call-info"),
  callDirection: $("call-direction"),
  callRemote:    $("call-remote"),
  callTimer:     $("call-timer"),
  callState:     $("call-state"),
  btnCall:       $("btn-call"),
  btnAnswer:     $("btn-answer"),
  btnHangup:     $("btn-hangup"),
  btnReject:     $("btn-reject"),
  btnMute:       $("btn-mute"),
  btnHold:       $("btn-hold"),
  incallControls:$("incall-controls"),
  transferDialog:$("transfer-dialog"),
  transferTarget:$("transfer-target"),
  remoteAudio:   $("remote-audio"),
  ringtone:      $("ringtone"),
  historyList:   $("history-list"),
  historyEmpty:  $("history-empty"),
  dashContent:   $("dashboard-content"),
  settingsBody:  $("settings-body"),
  settingsChevron:$("settings-chevron"),
  historyBody:   $("history-body"),
  historyChevron:$("history-chevron"),
  dashBody:      $("dashboard-body"),
  dashChevron:   $("dashboard-chevron"),
};

/* ---------- State ---------- */
let phone    = null;   // JsSIP.UA
let session  = null;   // current RTCSession
let isMuted  = false;
let isOnHold = false;
let timerInterval = null;
let callStart = null;
const callHistory = [];

/* ---------- Settings persistence ---------- */
function saveSettings() {
  const settings = {
    wsUrl:       ui.wsUrl.value,
    sipDomain:   ui.sipDomain.value,
    sipUser:     ui.sipUser.value,
    displayName: ui.displayName.value,
    iceStun:     ui.iceStun.checked,
    stunUrl:     ui.stunUrl.value,
  };
  try { localStorage.setItem("phone_settings", JSON.stringify(settings)); } catch (_) {}
}

function loadSettings() {
  try {
    const s = JSON.parse(localStorage.getItem("phone_settings"));
    if (!s) return;
    if (s.wsUrl)       ui.wsUrl.value       = s.wsUrl;
    if (s.sipDomain)   ui.sipDomain.value   = s.sipDomain;
    if (s.sipUser)     ui.sipUser.value     = s.sipUser;
    if (s.displayName) ui.displayName.value = s.displayName;
    if (s.stunUrl)     ui.stunUrl.value     = s.stunUrl;
    if (typeof s.iceStun === "boolean") ui.iceStun.checked = s.iceStun;
  } catch (_) {}
}

/* ---------- Panel toggles ---------- */
function toggleSettings() {
  ui.settingsBody.classList.toggle("collapsed");
  ui.settingsChevron.classList.toggle("open");
  ui.settingsChevron.textContent = ui.settingsBody.classList.contains("collapsed") ? "▶" : "▼";
}
function toggleHistory() {
  ui.historyBody.classList.toggle("collapsed");
  ui.historyChevron.classList.toggle("open");
  ui.historyChevron.textContent = ui.historyBody.classList.contains("collapsed") ? "▶" : "▼";
}
function toggleDashboard() {
  ui.dashBody.classList.toggle("collapsed");
  ui.dashChevron.classList.toggle("open");
  ui.dashChevron.textContent = ui.dashBody.classList.contains("collapsed") ? "▶" : "▼";
  if (!ui.dashBody.classList.contains("collapsed")) refreshDashboard();
}

/* ---------- Registration helpers ---------- */
function setRegState(state, text) {
  ui.regIndicator.className = "indicator " + state;
  ui.regStatus.textContent  = text;
}

/* ---------- Connect / Disconnect ---------- */
function connectPhone() {
  const wsUrl   = ui.wsUrl.value.trim();
  const domain  = ui.sipDomain.value.trim();
  const user    = ui.sipUser.value.trim();
  const pass    = ui.sipPass.value;
  const display = ui.displayName.value.trim();

  if (!wsUrl || !domain || !user) {
    alert("Please fill WebSocket URL, SIP Domain, and Extension.");
    return;
  }

  saveSettings();
  setRegState("connecting", "Connecting…");

  const socket = new JsSIP.WebSocketInterface(wsUrl);
  const config = {
    sockets:            [socket],
    uri:                `sip:${user}@${domain}`,
    password:           pass,
    display_name:       display || user,
    register:           true,
    session_timers:     false,
    user_agent:         "FreeSWITCH-WebRTC-Phone/1.0",
    connection_recovery_min_interval: 2,
    connection_recovery_max_interval: 30,
  };

  phone = new JsSIP.UA(config);

  phone.on("connected",      ()  => setRegState("connecting", "Connected, registering…"));
  phone.on("disconnected",   ()  => setRegState("offline",    "Disconnected"));
  phone.on("registered",     ()  => {
    setRegState("registered", `Registered as ${user}@${domain}`);
    ui.btnConnect.classList.add("hidden");
    ui.btnDisconnect.classList.remove("hidden");
  });
  phone.on("unregistered",   ()  => setRegState("offline",    "Unregistered"));
  phone.on("registrationFailed", (e) => {
    setRegState("error", `Registration failed: ${e.cause || "unknown"}`);
  });

  phone.on("newRTCSession", (data) => {
    if (data.originator === "remote") handleIncomingCall(data.session);
  });

  phone.start();
}

function disconnectPhone() {
  if (phone) {
    phone.stop();
    phone = null;
  }
  setRegState("offline", "Not connected");
  ui.btnConnect.classList.remove("hidden");
  ui.btnDisconnect.classList.add("hidden");
  resetCallUI();
}

/* ---------- Outbound call ---------- */
function makeCall() {
  if (!phone) { alert("Connect first."); return; }
  const target = ui.dialInput.value.trim();
  if (!target) return;

  const domain = ui.sipDomain.value.trim();
  const uri    = target.includes("@") ? `sip:${target}` : `sip:${target}@${domain}`;

  const iceServers = [];
  if (ui.iceStun.checked && ui.stunUrl.value.trim()) {
    iceServers.push({ urls: ui.stunUrl.value.trim() });
  }

  const options = {
    mediaConstraints: { audio: true, video: false },
    pcConfig: { iceServers },
    rtcOfferConstraints: { offerToReceiveAudio: true, offerToReceiveVideo: false },
  };

  session = phone.call(uri, options);
  setupSessionEvents(session, "outgoing");
  showCallUI("outgoing", target, "Calling…");
}

/* ---------- Incoming call ---------- */
function handleIncomingCall(incomingSession) {
  if (session) {
    incomingSession.terminate({ status_code: 486, reason_phrase: "Busy Here" });
    return;
  }
  session = incomingSession;
  setupSessionEvents(session, "incoming");

  const remote = session.remote_identity.uri.user || session.remote_identity.display_name || "Unknown";
  showCallUI("incoming", remote, "Ringing…");
  ui.btnCall.classList.add("hidden");
  ui.btnAnswer.classList.remove("hidden");
  ui.btnReject.classList.remove("hidden");

  try { ui.ringtone.play().catch(() => {}); } catch (_) {}
}

function answerCall() {
  if (!session) return;
  const iceServers = [];
  if (ui.iceStun.checked && ui.stunUrl.value.trim()) {
    iceServers.push({ urls: ui.stunUrl.value.trim() });
  }
  session.answer({
    mediaConstraints: { audio: true, video: false },
    pcConfig: { iceServers },
  });
  stopRingtone();
}

function rejectCall() {
  if (!session) return;
  session.terminate({ status_code: 486, reason_phrase: "Busy Here" });
  stopRingtone();
}

/* ---------- Session events ---------- */
function setupSessionEvents(s, direction) {
  s.on("progress", () => {
    updateCallState(direction === "outgoing" ? "Ringing…" : "Ringing…", "ringing");
  });

  s.on("accepted", () => {
    updateCallState("Connected", "active");
    startTimer();
    ui.btnAnswer.classList.add("hidden");
    ui.btnReject.classList.add("hidden");
    ui.btnCall.classList.add("hidden");
    ui.btnHangup.classList.remove("hidden");
    ui.incallControls.classList.remove("hidden");
    stopRingtone();
  });

  s.on("confirmed", () => {
    updateCallState("In call", "active");
  });

  s.on("peerconnection", (data) => {
    data.peerconnection.addEventListener("track", (ev) => {
      if (ev.streams && ev.streams[0]) {
        ui.remoteAudio.srcObject = ev.streams[0];
      }
    });
  });

  s.on("ended", (data) => {
    addHistory(direction, s.remote_identity.uri.user || "Unknown", callStart, data.cause);
    endCall();
  });

  s.on("failed", (data) => {
    addHistory(direction, s.remote_identity.uri.user || "Unknown", callStart, data.cause);
    endCall();
  });
}

/* ---------- Hang up ---------- */
function hangupCall() {
  if (!session) return;
  session.terminate();
}

/* ---------- Mute ---------- */
function toggleMute() {
  if (!session) return;
  if (isMuted) {
    session.unmute({ audio: true });
    isMuted = false;
    ui.btnMute.classList.remove("active");
    ui.btnMute.querySelector("span").textContent = "Mute";
  } else {
    session.mute({ audio: true });
    isMuted = true;
    ui.btnMute.classList.add("active");
    ui.btnMute.querySelector("span").textContent = "Unmute";
  }
}

/* ---------- Hold ---------- */
function toggleHold() {
  if (!session) return;
  if (isOnHold) {
    session.unhold();
    isOnHold = false;
    ui.btnHold.classList.remove("active");
    ui.btnHold.querySelector("span").textContent = "Hold";
    updateCallState("In call", "active");
  } else {
    session.hold();
    isOnHold = true;
    ui.btnHold.classList.add("active");
    ui.btnHold.querySelector("span").textContent = "Unhold";
    updateCallState("On hold", "on-hold");
  }
}

/* ---------- Transfer ---------- */
function initiateTransfer() {
  ui.transferDialog.classList.toggle("hidden");
  ui.transferTarget.focus();
}

function executeTransfer(attended) {
  if (!session) return;
  const target = ui.transferTarget.value.trim();
  if (!target) return;
  const domain = ui.sipDomain.value.trim();
  const uri = target.includes("@") ? target : `sip:${target}@${domain}`;

  if (attended) {
    session.refer(uri);
  } else {
    session.refer(uri);
  }
  cancelTransfer();
}

function cancelTransfer() {
  ui.transferDialog.classList.add("hidden");
  ui.transferTarget.value = "";
}

/* ---------- DTMF ---------- */
function toggleDTMFPad() {
  const pad = $("dialpad");
  pad.style.display = pad.style.display === "none" ? "grid" : "none";
}

/* ---------- Dialpad key press ---------- */
function pressKey(key) {
  if (session && (session.isEstablished && session.isEstablished())) {
    session.sendDTMF(key);
  }
  ui.dialInput.value += key;
}

/* ---------- UI helpers ---------- */
function showCallUI(direction, remote, stateText) {
  ui.callInfo.classList.remove("hidden");
  ui.callDirection.textContent = direction === "incoming" ? "Incoming call" : "Outgoing call";
  ui.callRemote.textContent = remote;
  updateCallState(stateText, "ringing");
  ui.dialInput.classList.add("hidden");
  ui.btnCall.classList.add("hidden");
  ui.btnHangup.classList.remove("hidden");
}

function updateCallState(text, cssClass) {
  ui.callState.textContent = text;
  ui.callState.className = "call-state " + (cssClass || "");
}

function resetCallUI() {
  session = null;
  isMuted = false;
  isOnHold = false;
  stopTimer();
  ui.callInfo.classList.add("hidden");
  ui.dialInput.classList.remove("hidden");
  ui.btnCall.classList.remove("hidden");
  ui.btnAnswer.classList.add("hidden");
  ui.btnHangup.classList.add("hidden");
  ui.btnReject.classList.add("hidden");
  ui.incallControls.classList.add("hidden");
  ui.transferDialog.classList.add("hidden");
  ui.btnMute.classList.remove("active");
  ui.btnHold.classList.remove("active");
  ui.btnMute.querySelector("span").textContent = "Mute";
  ui.btnHold.querySelector("span").textContent = "Hold";
  ui.remoteAudio.srcObject = null;
  stopRingtone();
}

function endCall() {
  resetCallUI();
}

/* ---------- Timer ---------- */
function startTimer() {
  callStart = new Date();
  ui.callTimer.textContent = "00:00";
  timerInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - callStart.getTime()) / 1000);
    const m = String(Math.floor(elapsed / 60)).padStart(2, "0");
    const s = String(elapsed % 60).padStart(2, "0");
    ui.callTimer.textContent = `${m}:${s}`;
  }, 1000);
}

function stopTimer() {
  if (timerInterval) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
  callStart = null;
  ui.callTimer.textContent = "00:00";
}

function stopRingtone() {
  try {
    ui.ringtone.pause();
    ui.ringtone.currentTime = 0;
  } catch (_) {}
}

/* ---------- Call History ---------- */
function addHistory(direction, number, startTime, cause) {
  const now = new Date();
  const duration = startTime ? Math.floor((now.getTime() - startTime.getTime()) / 1000) : 0;
  const entry = { direction, number, time: now, duration, cause: cause || "normal" };
  callHistory.unshift(entry);
  if (callHistory.length > 50) callHistory.pop();
  renderHistory();
}

function renderHistory() {
  ui.historyEmpty.classList.toggle("hidden", callHistory.length > 0);
  ui.historyList.innerHTML = callHistory.map((h) => {
    const icon = h.direction === "incoming"
      ? (h.duration > 0 ? "📥" : "📵")
      : (h.duration > 0 ? "📤" : "📵");
    const time = h.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const dur  = h.duration > 0 ? formatDuration(h.duration) : h.cause;
    return `<li>
      <span class="hist-icon">${icon}</span>
      <span class="hist-number">${escapeHtml(h.number)}</span>
      <span class="hist-duration">${dur}</span>
      <span class="hist-time">${time}</span>
    </li>`;
  }).join("");
}

function formatDuration(sec) {
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/* ---------- Queue Dashboard ---------- */
async function refreshDashboard() {
  try {
    const [queuesRes, agentsRes] = await Promise.all([
      fetch("/api/queues"),
      fetch("/api/agents"),
    ]);
    if (!queuesRes.ok || !agentsRes.ok) {
      ui.dashContent.textContent = "API unavailable";
      return;
    }
    const queues = await queuesRes.json();
    const agents = await agentsRes.json();

    let html = "";
    for (const q of queues) {
      let wb = {};
      try {
        const r = await fetch(`/api/wallboard/${q.number}`);
        if (r.ok) wb = await r.json();
      } catch (_) {}

      const members = agents.filter((a) =>
        a.queue_memberships && a.queue_memberships.includes(q.number)
      );

      html += `<div class="dash-queue">
        <h4>${escapeHtml(q.name)} (${escapeHtml(q.number)})</h4>
        <div class="dash-grid">
          <div class="dash-metric"><div class="label">Depth</div><div class="value">${wb.queue_depth ?? "–"}</div></div>
          <div class="dash-metric"><div class="label">SLA %</div><div class="value">${wb.service_level_20s != null ? wb.service_level_20s.toFixed(1) : "–"}</div></div>
          <div class="dash-metric"><div class="label">Abandon</div><div class="value">${wb.abandon_rate != null ? wb.abandon_rate.toFixed(1) + "%" : "–"}</div></div>
          <div class="dash-metric"><div class="label">Agents</div><div class="value">${members.length}</div></div>
        </div>
      </div>`;
    }
    ui.dashContent.innerHTML = html || "<div class='muted'>No queues configured</div>";
  } catch (err) {
    ui.dashContent.textContent = "Error loading dashboard: " + err.message;
  }
}

/* ---------- Keyboard support ---------- */
document.addEventListener("keydown", (e) => {
  if (document.activeElement === ui.dialInput || document.activeElement === ui.transferTarget) {
    if (e.key === "Enter") {
      e.preventDefault();
      if (document.activeElement === ui.transferTarget) return;
      if (session) return;
      makeCall();
    }
    return;
  }
  if (e.key === "Escape") {
    if (session) hangupCall();
  }
});

/* ---------- Init ---------- */
loadSettings();
JsSIP.debug.disable("JsSIP:*");

setInterval(() => {
  if (!ui.dashBody.classList.contains("collapsed")) refreshDashboard();
}, 15000);
