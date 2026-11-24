/* ==========================================================================
   TSH Hardware Monitor - page helpers (plain JavaScript, no libraries)

   1.  Auto refresh   - reloads data pages every few seconds, marked ?auto=1
                        so the server does not count it as "activity"
   2.  Refresh buttons
   3.  Table search + dropdown filters (work together)
   4.  Status dropdowns that submit themselves
   5.  Confirm before dangerous actions
   6.  Device form: parent host only for virtual machines
   7.  Show / hide password
   8.  Keyboard: "/" jumps to search, Esc clears it
   9.  Stop double clicks on submit buttons
   ========================================================================== */
(function () {
  "use strict";

  var $all = function (selector) { return document.querySelectorAll(selector); };

  // ---- 1. Auto refresh -----------------------------------------------------
  // Remove the ?auto=1 marker from the address bar once the page has loaded,
  // so a manual reload (F5) is counted as real activity.
  (function cleanAutoMarker() {
    var url = new URL(window.location.href);
    if (url.searchParams.has("auto")) {
      url.searchParams.delete("auto");
      window.history.replaceState(null, "", url.pathname + url.search + url.hash);
    }
  })();

  var seconds = parseInt(document.body.getAttribute("data-autorefresh"), 10);

  function userIsBusy() {
    var el = document.activeElement;
    if (el && (el.tagName === "INPUT" || el.tagName === "SELECT" || el.tagName === "TEXTAREA")) return true;
    // A search box or dropdown filter is in use: do not wipe the person's view
    var searching = Array.prototype.some.call($all("[data-filter]"), function (i) { return i.value.trim() !== ""; });
    var filtering = Array.prototype.some.call($all("[data-filter-select]"), function (s) { return s.value !== ""; });
    return searching || filtering;
  }

  if (seconds > 0) {
    setInterval(function () {
      if (document.hidden || userIsBusy()) return;
      var url = new URL(window.location.href);
      url.searchParams.set("auto", "1");
      window.location.replace(url.toString());
    }, seconds * 1000);
  }

  // ---- Live status feeds --------------------------------------------------
  function fetchFeed(url, consume) {
    var separator = url.indexOf("?") === -1 ? "?" : "&";
    fetch(url + separator + "auto=1", { credentials: "same-origin", cache: "no-store" })
      .then(function (response) {
        if (!response.ok) throw new Error("Status feed returned " + response.status);
        return response.json();
      })
      .then(consume)
      .catch(function (error) { console.warn("Live status update failed:", error.message); });
  }

  function setStatus(pill, state) {
    if (!pill) return;
    pill.className = "pill pill-" + state;
    var label = pill.querySelector("[data-device-status-label], [data-host-state-label]");
    if (label) label.textContent = state.charAt(0).toUpperCase() + state.slice(1);
  }

  var hostMetricsUrl = document.body.getAttribute("data-host-metrics-url");
  if (hostMetricsUrl) {
    var hostEvery = Math.max(5, parseInt(document.body.getAttribute("data-host-metrics-every"), 10) || 15);
    var updateHosts = function () {
      fetchFeed(hostMetricsUrl, function (payload) {
        (payload.hosts || []).forEach(function (host) {
          var card = document.querySelector('[data-host-card="' + host.id + '"]');
          if (!card) return;
          setStatus(card.querySelector("[data-host-state]"), host.state);
          ["cpu", "memory", "disk"].forEach(function (metric) {
            var value = host[metric];
            var text = card.querySelector('[data-host-metric="' + metric + '"]');
            var bar = card.querySelector('[data-host-metric-bar="' + metric + '"]');
            var track = bar && bar.closest(".bar");
            if (text) text.textContent = value === null || value === undefined ? "Unknown" : Math.round(value) + "%";
            if (bar) bar.style.width = value === null || value === undefined ? "0%" : value + "%";
            if (bar && track) {
              bar.classList.remove("bar-threat", "bar-warn");
              if (value !== null && value !== undefined) {
                if (value >= Number(track.getAttribute("data-threat-at"))) bar.classList.add("bar-threat");
                else if (value >= Number(track.getAttribute("data-warn-at"))) bar.classList.add("bar-warn");
              }
            }
          });
          var checked = card.querySelector("[data-host-last-checked]");
          if (checked && host.last_checked) checked.textContent = "Last checked " + host.last_checked;
        });
      });
    };
    updateHosts();
    window.setInterval(updateHosts, hostEvery * 1000);
  }

  var deviceStatusUrl = document.body.getAttribute("data-device-status-url");
  if (deviceStatusUrl) {
    var deviceEvery = Math.max(5, parseInt(document.body.getAttribute("data-device-status-every"), 10) || 15);
    var updateDevices = function () {
      fetchFeed(deviceStatusUrl, function (payload) {
        (payload.devices || []).forEach(function (device) {
          var row = document.querySelector('[data-device-id="' + device.id + '"]');
          if (!row) return;
          setStatus(row.querySelector("[data-device-status]"), device.status);
          var checked = row.querySelector("[data-device-last-checked]");
          if (checked) checked.textContent = device.last_check_label || "Waiting for first check";
          var kpis = row.querySelector("[data-ap-kpis]");
          if (kpis) {
            ["connected_clients", "channel_utilization", "avg_rssi", "dns_latency_ms", "dhcp_latency_ms"].forEach(function (key) {
              var output = kpis.querySelector('[data-ap-metric="' + key + '"]');
              var value = device[key];
              if (!output) return;
              if (value === null || value === undefined) output.textContent = "—";
              else if (key === "channel_utilization") output.textContent = value + "%";
              else if (key === "avg_rssi") output.textContent = value + " dBm";
              else if (key === "dns_latency_ms" || key === "dhcp_latency_ms") output.textContent = value + " ms";
              else output.textContent = value;
            });
          }
        });
      });
    };
    updateDevices();
    window.setInterval(updateDevices, deviceEvery * 1000);
  }

  // ---- 2. Refresh buttons --------------------------------------------------
  $all("[data-print]").forEach(function (btn) {
    btn.addEventListener("click", function () { window.print(); });
  });
  $all("[data-reload]").forEach(function (btn) {
    btn.addEventListener("click", function () { window.location.reload(); });
  });

  // ---- 3. Table search + dropdown filters ----------------------------------
  var tableState = {};

  function stateFor(id) {
    if (!tableState[id]) tableState[id] = { q: "", selects: {} };
    return tableState[id];
  }

  function applyFilters(id) {
    var table = document.getElementById(id);
    if (!table) return;
    var st = stateFor(id);
    var shown = 0;

    table.querySelectorAll("tbody tr[data-search]").forEach(function (row) {
      var match = row.getAttribute("data-search").indexOf(st.q) !== -1;
      Object.keys(st.selects).forEach(function (key) {
        if (st.selects[key] && row.getAttribute("data-" + key) !== st.selects[key]) match = false;
      });
      row.hidden = !match;
      if (match) shown++;
    });

    var empty = table.querySelector("tr.no-results");
    if (empty) empty.hidden = shown !== 0;
  }

  $all("[data-filter]").forEach(function (input) {
    var id = input.getAttribute("data-filter");
    input.addEventListener("input", function () {
      stateFor(id).q = input.value.trim().toLowerCase();
      applyFilters(id);
    });
  });

  $all("[data-filter-select]").forEach(function (select) {
    var id = select.getAttribute("data-filter-select");
    var key = select.getAttribute("data-key");
    select.addEventListener("change", function () {
      stateFor(id).selects[key] = select.value;
      applyFilters(id);
    });
  });

  // ---- 4. Status dropdowns submit on change --------------------------------
  $all("[data-autosubmit]").forEach(function (select) {
    select.addEventListener("change", function () { select.form.submit(); });
  });

  // ---- 5. Confirm dangerous actions ----------------------------------------
  $all("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) event.preventDefault();
    });
  });

  // ---- 6. Device form: parent host only matters for virtual machines -------
  var typeSelect = document.querySelector("[data-type-select]");
  var parentSelect = document.querySelector("[data-parent-select]");
  if (typeSelect && parentSelect) {
    var syncParent = function () { parentSelect.disabled = typeSelect.value !== "vm"; };
    typeSelect.addEventListener("change", syncParent);
    syncParent();
  }

  // ---- 7. Show / hide password ---------------------------------------------
  $all("[data-toggle-password]").forEach(function (btn) {
    btn.setAttribute("aria-pressed", "false");
    btn.addEventListener("click", function () {
      var input = document.getElementById("password");
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
      btn.setAttribute("aria-pressed", show ? "true" : "false");
    });
  });

  // ---- 8. Keyboard shortcuts ------------------------------------------------
  var firstSearch = document.querySelector("[data-filter]");
  if (firstSearch) {
    document.addEventListener("keydown", function (event) {
      var el = document.activeElement;
      var typing = el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.tagName === "SELECT");
      if (event.key === "/" && !typing && !event.ctrlKey && !event.metaKey && !event.altKey) {
        event.preventDefault();
        firstSearch.focus();
      }
    });
    $all("[data-filter]").forEach(function (input) {
      input.addEventListener("keydown", function (event) {
        if (event.key === "Escape" && input.value) {
          input.value = "";
          input.dispatchEvent(new Event("input"));
        }
      });
    });
  }

  // ---- 9. Stop double submits ----------------------------------------------
  $all("form").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (event.defaultPrevented) return;
      var button = form.querySelector('button[type="submit"]');
      if (button) setTimeout(function () { button.disabled = true; }, 0);
    });
  });
})();

/* ==========================================================================
   SOC notifications: pop-up alerts, optional sound, alert count in the tab title.

   The page asks /api/notifications every few seconds (marked ?auto=1 so it does
   not count as activity and the idle sign-out still works). Red pop-ups stay
   until dismissed or until the alert is acknowledged; amber ones fade after 15 s.
   Pop-ups are remembered in sessionStorage because the page reloads itself.
   ========================================================================== */
(function () {
  "use strict";

  var body = document.body;
  var feedUrl = body.getAttribute("data-notify-url");
  var host = document.getElementById("toast-host");
  if (!feedUrl || !host) return;                       // login page, or signed out

  var everyMs = Math.max(3, parseInt(body.getAttribute("data-notify-every"), 10) || 5) * 1000;
  var serverMax = parseInt(body.getAttribute("data-max-alert"), 10) || 0;
  var MAX_TOASTS = 4, WARNING_MS = 15000;
  var baseTitle = document.title;

  // ---- storage helpers (browsers can block storage: never let that break the page)
  function store(kind) { try { return window[kind]; } catch (e) { return null; } }
  function read(kind, key, fallback) {
    try { var v = store(kind).getItem(key); return v === null ? fallback : v; } catch (e) { return fallback; }
  }
  function write(kind, key, value) { try { store(kind).setItem(key, value); } catch (e) { /* ignore */ } }

  // The highest alert already shown. On the very first visit start from "now", so
  // opening the dashboard never shows a pile of old alerts.
  var lastSeen = parseInt(read("sessionStorage", "tsh_last_alert", ""), 10);
  if (isNaN(lastSeen) || lastSeen > serverMax) lastSeen = serverMax;   // also covers a reset database
  write("sessionStorage", "tsh_last_alert", String(lastSeen));

  // Pop-ups still on screen: { id: { item: {...}, expires: ms or 0 } }
  var active = {};
  try { active = JSON.parse(read("sessionStorage", "tsh_toasts", "{}")) || {}; } catch (e) { active = {}; }
  function saveActive() { write("sessionStorage", "tsh_toasts", JSON.stringify(active)); }

  // ---- sound ------------------------------------------------------------------
  var soundBtn = document.querySelector("[data-sound-toggle]");
  var soundOn = read("localStorage", "tsh_sound", "0") === "1";
  var audio = null;

  function audioContext() {
    if (audio) return audio;
    var Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return null;
    try { audio = new Ctx(); } catch (e) { audio = null; }
    return audio;
  }
  function beep(freq, start, length) {
    var ctx = audioContext();
    if (!ctx) return;
    var osc = ctx.createOscillator(), gain = ctx.createGain();
    osc.type = "square"; osc.frequency.value = freq;
    gain.gain.setValueAtTime(0.0001, ctx.currentTime + start);
    gain.gain.exponentialRampToValueAtTime(0.18, ctx.currentTime + start + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + start + length);
    osc.connect(gain); gain.connect(ctx.destination);
    osc.start(ctx.currentTime + start); osc.stop(ctx.currentTime + start + length + 0.02);
  }
  function alarm(severity) {
    if (!soundOn) return;
    var ctx = audioContext();
    if (!ctx) return;
    if (ctx.state === "suspended" && ctx.resume) ctx.resume();
    if (severity === "threat") { beep(880, 0, 0.18); beep(660, 0.22, 0.18); beep(880, 0.44, 0.18); beep(660, 0.66, 0.18); }
    else { beep(660, 0, 0.2); }
  }
  function paintSound() {
    if (!soundBtn) return;
    var blocked = soundOn && audio && audio.state === "suspended";
    var label = !soundOn ? "Alert sound: off (click to turn on)"
              : blocked ? "Alert sound: on, but the browser needs one click on the page" : "Alert sound: on";
    soundBtn.setAttribute("aria-pressed", soundOn ? "true" : "false");
    soundBtn.setAttribute("aria-label", label);
    soundBtn.title = label;
    soundBtn.style.opacity = blocked ? ".55" : "";
  }
  if (soundBtn) {
    soundBtn.addEventListener("click", function () {
      soundOn = !soundOn;
      write("localStorage", "tsh_sound", soundOn ? "1" : "0");
      if (soundOn) { var ctx = audioContext(); if (ctx && ctx.resume) ctx.resume(); beep(660, 0, 0.12); }  // a click is needed for browsers to allow sound
      paintSound();
    });
    // After the page reloads itself, the first click anywhere re-enables the sound
    var wake = function () {
      if (soundOn) { var ctx = audioContext(); if (ctx && ctx.resume) ctx.resume().then(paintSound); }
    };
    document.addEventListener("pointerdown", wake, { once: true });
    document.addEventListener("keydown", wake, { once: true });
    paintSound();
  }

  // ---- pop-ups ------------------------------------------------------------------
  var ICON = '<svg class="icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
  var CLOSE = '<svg class="icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>';

  function safeUrl(u) { return typeof u === "string" && u.charAt(0) === "/" && u.charAt(1) !== "/" && u.indexOf("\\") === -1 ? u : "/alerts"; }

  function removeToast(id, remember) {
    var el = host.querySelector('[data-toast="' + id + '"]');
    if (el) el.remove();
    if (remember !== false) { delete active[id]; saveActive(); }
  }

  function showToast(item, expiresAt) {
    if (host.querySelector('[data-toast="' + item.id + '"]')) return;
    var warning = item.severity !== "threat";
    var box = document.createElement("div");
    box.className = "toast toast-" + (warning ? "warning" : "threat");
    box.setAttribute("role", "alert");
    box.setAttribute("data-toast", item.id);

    var icon = document.createElement("span"); icon.className = "toast-icon"; icon.innerHTML = ICON;   // fixed markup, no alert text
    var main = document.createElement("div"); main.className = "toast-body";
    var title = document.createElement("div"); title.className = "toast-title";
    title.textContent = (warning ? "WARNING · " : "THREAT · ") + item.title;
    var text = document.createElement("div"); text.className = "toast-text";
    text.textContent = item.device + (item.port ? " · port " + item.port : "") + " · " + item.message;
    var link = document.createElement("a"); link.className = "toast-link"; link.href = safeUrl(item.url); link.textContent = "Open";
    main.appendChild(title); main.appendChild(text); main.appendChild(link);
    var close = document.createElement("button");
    close.type = "button"; close.className = "toast-close"; close.setAttribute("aria-label", "Dismiss alert"); close.innerHTML = CLOSE;
    close.addEventListener("click", function () { removeToast(item.id); });
    box.appendChild(icon); box.appendChild(main); box.appendChild(close);
    host.appendChild(box);

    while (host.children.length > MAX_TOASTS) {                // keep the newest, drop the oldest
      var first = host.firstElementChild; delete active[first.getAttribute("data-toast")]; first.remove();
    }
    active[item.id] = { item: item, expires: warning ? (expiresAt || Date.now() + WARNING_MS) : 0 };
    saveActive();
  }

  // Put back pop-ups that were still open before the page reloaded itself
  Object.keys(active).forEach(function (id) {
    var a = active[id];
    if (!a || !a.item || (a.expires && a.expires < Date.now())) { delete active[id]; return; }
    showToast(a.item, a.expires);
  });
  saveActive();

  setInterval(function () {                                    // fade amber pop-ups
    var now = Date.now();
    Object.keys(active).forEach(function (id) { if (active[id].expires && active[id].expires < now) removeToast(id); });
  }, 1000);

  // ---- tab title -------------------------------------------------------------------
  function paintTitle(summary) {
    var n = (summary.threats || 0) + (summary.switches_offline || 0);
    document.title = n > 0 ? "(" + n + ") ALERT · " + baseTitle : baseTitle;
  }

  // ---- polling -----------------------------------------------------------------------
  var failures = 0;
  function poll() {
    var url = feedUrl + (feedUrl.indexOf("?") === -1 ? "?" : "&") + "auto=1&since=" + lastSeen;
    fetch(url, { credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json" } })
      .then(function (res) {
        if (res.redirected || res.status === 401) { window.location.assign("/login"); throw new Error("signed out"); }
        if (!res.ok) throw new Error("HTTP " + res.status);
        return res.json();
      })
      .then(function (data) {
        failures = 0;
        var open = {};
        (data.open_ids || []).forEach(function (id) { open[id] = true; });
        Object.keys(active).forEach(function (id) { if (!open[id] && id !== "more") removeToast(id); });   // acknowledged or resolved elsewhere

        var items = data.items || [];
        var show = items.length > MAX_TOASTS ? items.slice(-(MAX_TOASTS - 1)) : items;
        var loudest = null;
        show.forEach(function (it) { showToast(it); if (it.severity === "threat") loudest = "threat"; else if (!loudest) loudest = "warning"; });
        if (items.length > show.length) {
          showToast({ id: "more", severity: "warning", title: (items.length - show.length) + " more new alerts", device: "Several devices", port: "", message: "Open the alerts page to see all of them.", url: "/alerts" });
        }
        if (items.length) {
          lastSeen = Math.max(lastSeen, items[items.length - 1].id);
          write("sessionStorage", "tsh_last_alert", String(lastSeen));
          alarm(loudest);
        }
        if (data.summary) paintTitle(data.summary);
      })
      .catch(function () { failures += 1; });
  }
  poll();
  setInterval(function () { if (failures < 20) poll(); }, everyMs);   // stop hammering the server if it is down
})();
