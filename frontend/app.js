// warpalt frontend logic.
// Talks to the Go side through Wails bindings (window.go.<pkg>.App.*) and
// listens for state events; if events are unavailable it falls back to polling.

(function () {
  "use strict";

  // ---- binding access ----------------------------------------------------
  // The namespace follows the Go package that defines the bound struct
  // ("app"), but we also accept "main" so the file works unchanged if the
  // struct ever moves into package main.
  function backend() {
    const g = window.go;
    if (!g) return null;
    if (g.app && g.app.App) return g.app.App;
    if (g.main && g.main.App) return g.main.App;
    return null;
  }

  function call(method, ...args) {
    const be = backend();
    if (!be || typeof be[method] !== "function") {
      return Promise.reject(new Error("backend not ready (" + method + ")"));
    }
    try {
      return Promise.resolve(be[method](...args));
    } catch (e) {
      return Promise.reject(e);
    }
  }

  // ---- DOM helpers -------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };

  // ---- state -------------------------------------------------------------
  let status = null;
  let split = null;

  function showError(msg) {
    const b = $("error-banner");
    if (!msg) { b.hidden = true; return; }
    b.textContent = msg;
    b.hidden = false;
  }

  function renderStatus() {
    const pill = $("state-pill");
    const btn = $("toggle-btn");
    const orgLine = $("org-line");

    if (!status) {
      pill.textContent = "…";
      btn.disabled = true;
      return;
    }
    pill.dataset.state = status.state || "disconnected";
    pill.textContent = status.state || "disconnected";

    const running = ["connecting", "connected", "reconnecting"].includes(status.state);
    btn.textContent = running ? "Disable" : "Enable";
    btn.disabled = !status.enrolled;
    btn.classList.toggle("primary", !running);

    if (status.enrolled) {
      orgLine.textContent = (status.team || "personal") + " · " + (status.deviceName || "");
    } else {
      orgLine.textContent = "not enrolled";
    }

    if (status.lastError) showError(status.lastError);

    // view switch
    $("view-enroll").hidden = status.enrolled;
    $("view-main").hidden = !status.enrolled;

    if (status.enrolled) renderDeviceTab();
  }

  function renderDeviceTab() {
    const dl = $("device-kv");
    dl.innerHTML = "";
    const rows = [
      ["Team", status.team || "—"],
      ["Device name", status.deviceName || "—"],
      ["Device ID", status.deviceId || "—"],
      ["Tunnel IPv4", status.ipv4 || "—"],
      ["Tunnel IPv6", status.ipv6 || "—"],
      ["MASQUE endpoint", status.endpoint || "—"],
      ["Interface", status.iface || "—"],
      ["State", status.state || "—"],
      ["Last error", status.lastError || "—"],
    ];
    for (const [k, v] of rows) {
      dl.appendChild(el("dt", null, k));
      dl.appendChild(el("dd", null, v));
    }
  }

  function renderSplit() {
    if (!split) return;

    const badge = $("mode-badge");
    badge.dataset.mode = split.mode;
    badge.textContent = split.mode || "—";
    $("mode-desc").textContent = split.mode === "exclude"
      ? "All traffic goes through the tunnel except listed destinations."
      : "Only listed destinations go through the tunnel.";

    $("mode-source").innerHTML = "";
    const src = el("span", null, split.modeSource === "organization" ? "mode from " : "mode set locally, ");
    $("mode-source").appendChild(src);
    if (split.modeSource === "organization") {
      $("mode-source").appendChild(el("b", null, "organization profile"));
    }

    // remote note / errors
    const note = $("remote-note");
    if (split.remoteAvailable) {
      note.textContent = split.remoteNote || "";
      note.style.color = "var(--muted)";
    } else {
      note.textContent = (split.remoteNote || "Organization settings unavailable.") +
        " Falling back to local mode and Cloudflare's default exclusions.";
      note.style.color = "var(--warn)";
    }
    $("local-mode-box").hidden = split.remoteAvailable;

    const sel = $("local-mode");
    if (split.localMode) sel.value = split.localMode;

    // org entries
    const orgList = $("org-list");
    orgList.innerHTML = "";
    for (const e of split.orgEntries || []) {
      orgList.appendChild(entryRow(e, false));
    }
    $("org-empty").hidden = (split.orgEntries || []).length > 0;

    // local entries
    const localList = $("local-list");
    localList.innerHTML = "";
    for (const e of split.localEntries || []) {
      localList.appendChild(entryRow(e, true));
    }

    // conflicts
    const cl = $("conflict-list");
    cl.innerHTML = "";
    for (const c of split.conflicts || []) {
      const li = el("li");
      const code = el("code", null, c.local);
      li.appendChild(code);
      li.appendChild(document.createTextNode(
        " overlaps your organization's entry " + c.org +
        " — your local entry wins for exactly this address."
      ));
      cl.appendChild(li);
    }

    // warnings
    const warnCard = $("warnings-card");
    const warnList = $("warning-list");
    warnList.innerHTML = "";
    const warnings = split.warnings || [];
    warnCard.hidden = warnings.length === 0;
    for (const w of warnings) warnList.appendChild(el("li", null, w));
  }

  function entryRow(e, removable) {
    const li = el("li");
    li.appendChild(el("span", "kind", e.kind === "host" ? "host" : "ip"));
    li.appendChild(el("span", null, e.value));
    if (e.description) li.appendChild(el("span", "desc", e.description));
    li.appendChild(el("span", "spacer"));
    if (removable) {
      const rm = el("button", "rm", "✕");
      rm.title = "Remove local entry";
      rm.addEventListener("click", async () => {
        try {
          split = await call("RemoveLocalRoute", e.value);
          renderSplit();
        } catch (err) { showError(String(err)); }
      });
      li.appendChild(rm);
    }
    return li;
  }

  // ---- actions -----------------------------------------------------------
  async function refreshAll() {
    try { status = await call("GetStatus"); renderStatus(); } catch (_) {}
    try { split = await call("GetSplit"); renderSplit(); } catch (_) {}
  }

  $("toggle-btn").addEventListener("click", async () => {
    $("toggle-btn").disabled = true;
    try {
      status = await call("Toggle");
      if (status && status.lastError) showError(status.lastError);
      else showError("");
    } catch (e) { showError(String(e)); }
    renderStatus();
    try { split = await call("GetSplit"); renderSplit(); } catch (_) {}
    $("toggle-btn").disabled = false;
  });

  $("open-page-btn").addEventListener("click", async () => {
    try {
      await call("OpenEnrollmentPage", $("team").value);
    } catch (e) { showError(String(e)); }
  });

  $("enroll-btn").addEventListener("click", async () => {
    const btn = $("enroll-btn");
    const statusLine = $("enroll-status");
    btn.disabled = true;
    statusLine.textContent = "Registering device…";
    try {
      const res = await call("Enroll", {
        team: $("team").value,
        token: $("token").value,
        deviceName: $("device-name").value,
        acceptTos: $("accept-tos").checked,
      });
      if (res && res.error) {
        statusLine.textContent = "";
        showError(res.error);
      } else {
        statusLine.textContent = "Enrolled.";
        showError("");
        status = res.status;
        renderStatus();
        setTimeout(refreshAll, 500);
      }
    } catch (e) {
      statusLine.textContent = "";
      showError(String(e));
    }
    btn.disabled = false;
  });

  $("local-add-btn").addEventListener("click", async () => {
    const input = $("local-input");
    try {
      split = await call("AddLocalRoute", input.value);
      input.value = "";
      showError("");
      renderSplit();
    } catch (e) { showError(String(e)); }
  });
  $("local-input").addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") $("local-add-btn").click();
  });

  $("refresh-policy-btn").addEventListener("click", async () => {
    const b = $("refresh-policy-btn");
    b.disabled = true;
    try { split = await call("RefreshPolicy"); renderSplit(); } catch (e) { showError(String(e)); }
    b.disabled = false;
  });

  $("local-mode").addEventListener("change", async (ev) => {
    try {
      await call("SetLocalMode", ev.target.value);
      split = await call("GetSplit");
      renderSplit();
    } catch (e) { showError(String(e)); }
  });

  $("logout-btn").addEventListener("click", async () => {
    try {
      await call("Logout");
      showError("");
      await refreshAll();
    } catch (e) { showError(String(e)); }
  });

  // tabs
  document.querySelectorAll(".tab").forEach((t) => {
    t.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
      t.classList.add("active");
      $("tab-split").hidden = t.dataset.tab !== "split";
      $("tab-device").hidden = t.dataset.tab !== "device";
    });
  });

  // ---- events ------------------------------------------------------------
  function wireEvents() {
    const rt = window.runtime;
    if (!rt || typeof rt.EventsOn !== "function") {
      // Fallback: poll.
      setInterval(refreshAll, 1500);
      return;
    }
    rt.EventsOn("warp:state", (payload) => {
      if (!status) return;
      status.state = payload.state;
      status.lastError = payload.error || "";
      if (payload.error) showError(payload.error); else showError("");
      renderStatus();
    });
    rt.EventsOn("warp:policy", (view) => { split = view; renderSplit(); });
    rt.EventsOn("warp:error", (msg) => showError(String(msg)));
  }

  // ---- boot --------------------------------------------------------------
  window.addEventListener("DOMContentLoaded", async () => {
    wireEvents();
    await refreshAll();
    // The backend may still be starting: retry until the first answer.
    let tries = 0;
    const iv = setInterval(async () => {
      if (status || tries++ > 20) { clearInterval(iv); return; }
      await refreshAll();
    }, 300);
  });
})();
