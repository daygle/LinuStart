"use strict";

/* ---------------------------------------------------------------- helpers */

const state = {
  token: localStorage.getItem("linustart_token") || "",
  view: "overview",
  session: null,
  sessionTimer: null,
  jobTimer: null,
  jobsTimer: null,
  openJob: null,
  jobLines: 0,
  installed: [],
  shells: [],
  editUser: null,
};

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));

function esc(value) {
  const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value === undefined || value === null ? "" : value).replace(/[&<>"']/g, (c) => map[c]);
}

function toast(message, kind = "info") {
  const box = document.createElement("div");
  box.className = `toast ${kind === "info" ? "" : kind}`;
  box.textContent = message;
  $("#toasts").appendChild(box);
  setTimeout(() => box.remove(), 5200);
}

function fmtBytes(bytes) {
  if (!bytes) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function fmtUptime(seconds) {
  if (!seconds) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

function meter(label, used, total) {
  const pct = total ? Math.min(100, Math.round((used / total) * 100)) : 0;
  const cls = pct > 90 ? "danger" : pct > 75 ? "warn" : "";
  return `
    <div class="meter">
      <div class="meter-label"><span>${esc(label)}</span><span>${fmtBytes(used)} / ${fmtBytes(total)} (${pct}%)</span></div>
      <div class="meter-track"><div class="meter-fill ${cls}" style="width:${pct}%"></div></div>
    </div>`;
}

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (state.token) headers["Authorization"] = `Bearer ${state.token}`;
  const init = { method: options.method || "GET", headers };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const res = await fetch(`/api${path}`, init);
  if (res.status === 401) {
    showTokenModal();
    throw new Error("Authentication required");
  }
  let data = {};
  try { data = await res.json(); } catch (e) { data = {}; }
  if (!res.ok) {
    const detail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data);
    throw new Error(detail || `Request failed (${res.status})`);
  }
  return data;
}

/* ------------------------------------------------------------------- auth */

function showTokenModal() { $("#token-modal").classList.remove("hidden"); }
function hideTokenModal() { $("#token-modal").classList.add("hidden"); }

$("#token-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = $("#token-input").value.trim();
  state.token = token;
  try {
    await api("/health");
    localStorage.setItem("linustart_token", token);
    hideTokenModal();
    toast("Connected", "success");
    loadView();
  } catch (err) {
    toast(err.message, "error");
  }
});

$("#logout").addEventListener("click", () => {
  localStorage.removeItem("linustart_token");
  state.token = "";
  showTokenModal();
});

/* --------------------------------------------------------------- routing */

const TITLES = {
  overview: "Overview",
  network: "Networking",
  system: "Hostname & Time",
  updates: "Unattended Updates",
  email: "Email",
  users: "Users",
  software: "Software",
  jobs: "Jobs",
  audit: "Audit Log",
};

const LOADERS = {
  overview: loadOverview,
  network: loadNetwork,
  system: loadSystem,
  updates: loadUpdates,
  email: loadMail,
  users: loadUsers,
  software: loadSoftware,
  jobs: loadJobs,
  audit: loadAudit,
};

function setView(name) {
  state.view = name;
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === name));
  $$(".view").forEach((view) => view.classList.add("hidden"));
  $(`#view-${name}`).classList.remove("hidden");
  $("#view-title").textContent = TITLES[name] || name;
  clearInterval(state.jobsTimer);
  loadView();
}

function loadView() {
  const loader = LOADERS[state.view];
  if (loader) loader().catch((err) => { if (err.message !== "Authentication required") toast(err.message, "error"); });
}

$("#nav").addEventListener("click", (event) => {
  const item = event.target.closest(".nav-item");
  if (item) setView(item.dataset.view);
});
$("#refresh").addEventListener("click", loadView);

/* --------------------------------------------------------------- overview */

async function loadOverview() {
  const data = await api("/system/overview");
  $("#server-label").textContent = data.hostname || "—";
  $("#overview-cards").innerHTML = `
    <div class="card"><h2>System</h2>
      <div class="stat-grid">
        <div class="stat"><div class="k">Hostname</div><div class="v">${esc(data.hostname)}</div></div>
        <div class="stat"><div class="k">OS</div><div class="v">${esc(data.os_name)}</div></div>
        <div class="stat"><div class="k">Kernel</div><div class="v">${esc(data.kernel)}</div></div>
        <div class="stat"><div class="k">Architecture</div><div class="v">${esc(data.arch)}</div></div>
        <div class="stat"><div class="k">Uptime</div><div class="v">${fmtUptime(data.uptime_seconds)}</div></div>
        <div class="stat"><div class="k">Load average</div><div class="v">${esc((data.load_average || []).join(" / "))}</div></div>
      </div>
    </div>`;
  const mem = data.memory || {};
  const disk = data.disk || {};
  $("#overview-resources").innerHTML =
    meter("Memory", mem.used, mem.total) +
    meter("Disk /", disk.used, disk.total) +
    `<div class="muted">${esc(data.cpus)} CPU core(s) · Python ${esc(data.python)}</div>`;
  try {
    const net = await api("/network");
    const rows = (net.runtime.interfaces || [])
      .map((iface) => `<li><code>${esc(iface.name)}</code> ${esc((iface.addresses || []).join(", ") || "no address")}</li>`)
      .join("");
    const route = net.runtime.default_route;
    $("#overview-addresses").innerHTML = `
      <ul class="list">${rows || "<li class='muted'>No interfaces found</li>"}</ul>
      <div class="muted">Default route: ${route ? `${esc(route.via || "")} via ${esc(route.dev || "")}` : "none"}</div>`;
  } catch (err) {
    $("#overview-addresses").innerHTML = `<div class="muted">${esc(err.message)}</div>`;
  }
}

/* ---------------------------------------------------------------- network */

async function loadNetwork() {
  const data = await api("/network");
  $("#net-backend").textContent = `backend: ${data.backend}`;
  $("#net-source").textContent = (data.config && data.config.source) || "";
  const runtimeRows = (data.runtime.interfaces || []).map((iface) => `
    <tr>
      <td><code>${esc(iface.name)}</code></td>
      <td><span class="badge ${iface.state === "up" ? "ok" : "muted"}">${esc(iface.state)}</span></td>
      <td>${esc((iface.addresses || []).join(", "))}</td>
      <td class="muted">${esc(iface.mac || "")}</td>
    </tr>`).join("");
  $("#net-runtime-table").innerHTML = `
    <thead><tr><th>Interface</th><th>State</th><th>Addresses</th><th>MAC</th></tr></thead>
    <tbody>${runtimeRows || "<tr><td colspan='4' class='muted'>No interfaces found</td></tr>"}</tbody>`;

  const cards = (data.config.interfaces || []).map((iface) => {
    const method = iface.method || "dhcp";
    return `
    <div class="card">
      <h2>${esc(iface.name)} <span class="badge">${esc(method)}</span></h2>
      <form class="form" data-iface="${esc(iface.name)}">
        <label>Mode
          <select name="method">
            <option value="dhcp" ${method === "dhcp" ? "selected" : ""}>DHCP</option>
            <option value="static" ${method === "static" ? "selected" : ""}>Static</option>
            <option value="manual" ${method === "manual" ? "selected" : ""}>Manual</option>
          </select>
        </label>
        <label>Address (CIDR)
          <input type="text" name="address" value="${esc(iface.address || "")}" placeholder="192.168.1.10/24">
        </label>
        <label>Gateway
          <input type="text" name="gateway" value="${esc(iface.gateway || "")}" placeholder="192.168.1.1">
        </label>
        <label>DNS servers (comma separated)
          <input type="text" name="dns" value="${esc((iface.dns || []).join(", "))}" placeholder="1.1.1.1, 8.8.8.8">
        </label>
        <button class="btn btn-primary" type="submit">Apply (with 90s auto-revert)</button>
      </form>
    </div>`;
  }).join("");
  $("#net-config-cards").innerHTML = cards || "<div class='card muted'>No editable interfaces found</div>";

  $$("#net-config-cards form").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const name = form.dataset.iface;
      const el = form.elements; /* form.method would hit the DOM property, use elements */
      const body = {
        method: el.method.value,
        address: el.address.value.trim() || null,
        gateway: el.gateway.value.trim() || null,
        dns: el.dns.value.split(",").map((s) => s.trim()).filter(Boolean),
      };
      try {
        const result = await api(`/network/interfaces/${encodeURIComponent(name)}`, { method: "POST", body });
        toast(`Changes applied to ${name}`, "success");
        startRevertBar(result.session);
      } catch (err) {
        toast(err.message, "error");
      }
    });
  });

  (data.sessions || []).forEach(startRevertBar);
}

function hideRevertBar() {
  clearInterval(state.sessionTimer);
  state.session = null;
  $("#revert-bar").classList.add("hidden");
}

function startRevertBar(session) {
  if (!session) return;
  hideRevertBar();
  state.session = session;
  const bar = $("#revert-bar");
  bar.classList.remove("hidden");
  $("#revert-text").textContent =
    `Network changes applied to ${session.interface}. Confirm to keep them — otherwise they revert automatically.`;
  let left = session.seconds_left;
  const tick = () => {
    $("#revert-countdown").textContent = `revert in ${left}s`;
    left -= 1;
    if (left < 0) { hideRevertBar(); loadNetwork(); }
  };
  tick();
  state.sessionTimer = setInterval(tick, 1000);
}

$("#revert-confirm").addEventListener("click", async () => {
  if (!state.session) return;
  try {
    await api(`/network/sessions/${state.session.id}/confirm`, { method: "POST" });
    toast("Network configuration saved", "success");
  } catch (err) {
    toast(err.message, "error");
  }
  hideRevertBar();
});

$("#revert-discard").addEventListener("click", async () => {
  if (!state.session) return;
  try {
    await api(`/network/sessions/${state.session.id}/revert`, { method: "POST" });
    toast("Network changes reverted", "info");
  } catch (err) {
    toast(err.message, "error");
  }
  hideRevertBar();
  loadNetwork();
});

/* ----------------------------------------------------------------- system */

async function loadSystem() {
  const [host, tz] = await Promise.all([api("/hostname"), api("/timezone")]);
  $("#hostname-input").value = host.hostname || "";
  $("#timezone-input").value = tz.timezone || "";
  $("#timezone-list").innerHTML = (tz.zones || []).map((z) => `<option value="${esc(z)}"></option>`).join("");
  $("#ntp-status").textContent = tz.ntp
    ? `NTP enabled${tz.ntp_synchronized ? " · synchronized" : ""}`
    : "NTP disabled";
  $("#ntp-toggle").dataset.enabled = tz.ntp ? "1" : "0";
  $("#local-time").textContent = tz.local_time ? `Local time: ${tz.local_time}` : "";
}

$("#hostname-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await api("/hostname", { method: "POST", body: { hostname: $("#hostname-input").value.trim() } });
    toast(`Hostname set to ${result.hostname}`, "success");
    loadSystem();
  } catch (err) { toast(err.message, "error"); }
});

$("#timezone-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/timezone", { method: "POST", body: { timezone: $("#timezone-input").value.trim() } });
    toast("Timezone updated", "success");
    loadSystem();
  } catch (err) { toast(err.message, "error"); }
});

$("#ntp-toggle").addEventListener("click", async () => {
  const enabled = $("#ntp-toggle").dataset.enabled !== "1";
  try {
    await api("/ntp", { method: "POST", body: { enabled } });
    toast(`NTP ${enabled ? "enabled" : "disabled"}`, "success");
    loadSystem();
  } catch (err) { toast(err.message, "error"); }
});

/* ---------------------------------------------------------------- updates */

async function loadUpdates() {
  const data = await api("/updates");
  $("#uu-warning").classList.toggle("hidden", data.package_installed !== false);
  $("#uu-enabled").checked = !!data.enabled;
  $("#uu-frequency").value = String(data.update_frequency_days || "1");
  $("#uu-reboot").checked = !!data.auto_reboot;
  $("#uu-reboot-time").value = data.auto_reboot_time || "";
  $("#uu-remove-unused").checked = data.remove_unused !== false;
  $("#uu-remove-deps").checked = !!data.remove_unused_dependencies;
  $("#uu-origins").innerHTML = (data.allowed_origins || []).map((o) => `<li><code>${esc(o)}</code></li>`).join("")
    || "<li class='muted'>No Allowed-Origins configured</li>";
  $("#uu-log").textContent = (data.log || []).slice(-60).join("\n") || "No unattended-upgrades activity yet.";
}

$("#updates-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/updates", {
      method: "POST",
      body: {
        enabled: $("#uu-enabled").checked,
        update_frequency_days: $("#uu-frequency").value,
        auto_reboot: $("#uu-reboot").checked,
        auto_reboot_time: $("#uu-reboot-time").value.trim(),
        remove_unused: $("#uu-remove-unused").checked,
        remove_unused_dependencies: $("#uu-remove-deps").checked,
      },
    });
    toast("Unattended updates configuration saved", "success");
    loadUpdates();
  } catch (err) { toast(err.message, "error"); }
});

$("#uu-install-uu").addEventListener("click", async () => {
  try {
    const job = await api("/packages/install", { method: "POST", body: { names: ["unattended-upgrades"] } });
    toast("Installing unattended-upgrades…", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

$("#uu-dry-run").addEventListener("click", async () => {
  try {
    const job = await api("/updates/dry-run", { method: "POST" });
    toast("Dry run started", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

/* ------------------------------------------------------------------ email */

async function loadMail() {
  const data = await api("/mail");
  const badge = $("#mail-status-badge");
  if (!data.installed) {
    badge.textContent = "postfix not installed";
    badge.className = "badge warn";
    $("#mail-install").classList.remove("hidden");
  } else {
    badge.textContent = data.service_active ? "postfix active" : "postfix installed";
    badge.className = `badge ${data.service_active ? "ok" : "warn"}`;
    $("#mail-install").classList.add("hidden");
  }
  $("#mail-host").value = data.host || "";
  $("#mail-port").value = data.port || 587;
  $("#mail-security").value = data.security || "starttls";
  $("#mail-username").value = data.username || "";
  $("#mail-from").value = data.from_address || "";
  $("#mail-report-to").value = data.report_to || "";
  $("#mail-report-mode").value = data.report_mode || "only-on-error";
  $("#mail-password-hint").textContent = data.credentials_set ? "(password on file)" : "";
  $("#mail-summary").textContent = data.relayhost
    ? `Mail is relayed via ${data.relayhost}, sending as ${data.from_address || "—"} (sender domain ${data.myorigin || "—"}).`
    : "No relay configured yet.";
}

$("#mail-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = {
    host: $("#mail-host").value.trim(),
    port: parseInt($("#mail-port").value.trim(), 10) || 587,
    security: $("#mail-security").value,
    username: $("#mail-username").value.trim(),
    password: $("#mail-password").value || null,
    from_address: $("#mail-from").value.trim(),
    report_to: $("#mail-report-to").value.trim(),
    report_mode: $("#mail-report-mode").value,
  };
  try {
    await api("/mail", { method: "POST", body });
    $("#mail-password").value = "";
    toast("Mail settings saved", "success");
    loadMail();
  } catch (err) { toast(err.message, "error"); }
});

$("#mail-test-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const job = await api("/mail/test", {
      method: "POST",
      body: { recipient: $("#mail-test-to").value.trim() },
    });
    toast("Test message queued", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

$("#mail-install").addEventListener("click", async () => {
  try {
    const job = await api("/mail/install", { method: "POST" });
    toast("Installing postfix…", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

/* ------------------------------------------------------------------ users */

async function loadUsers() {
  const data = await api("/users");
  state.shells = data.shells || [];
  $("#new-shell").innerHTML = state.shells.map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
  const rows = (data.users || []).map((u) => `
    <tr>
      <td><code>${esc(u.name)}</code></td>
      <td>${esc(u.full_name || "—")}</td>
      <td><code>${esc(u.shell)}</code></td>
      <td>
        ${u.sudo ? '<span class="badge ok">sudo</span> ' : ""}
        ${u.locked ? '<span class="badge warn">locked</span>' : '<span class="badge ok">active</span>'}
      </td>
      <td><button class="btn btn-small" data-user="${esc(u.name)}" data-action="edit">Edit</button></td>
    </tr>`).join("");
  $("#users-table").innerHTML = `
    <thead><tr><th>User</th><th>Full name</th><th>Shell</th><th>Status</th><th></th></tr></thead>
    <tbody>${rows || "<tr><td colspan='5' class='muted'>No user accounts found</td></tr>"}</tbody>`;
}

$("#users-table").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-user]");
  if (button) openUser(button.dataset.user);
});

async function openUser(name) {
  try {
    const data = await api(`/users/${encodeURIComponent(name)}`);
    state.editUser = name;
    const u = data.user;
    $("#user-modal-title").textContent = `${u.name} · uid ${u.uid}`;
    $("#edit-full-name").value = u.full_name || "";
    $("#edit-shell").innerHTML = state.shells.map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join("");
    $("#edit-shell").value = u.shell;
    $("#edit-sudo").checked = !!u.sudo;
    $("#edit-locked").checked = !!u.locked;
    $("#edit-password").value = "";
    $("#edit-key").value = "";
    renderKeys(data.keys || []);
    $("#user-modal").classList.remove("hidden");
  } catch (err) { toast(err.message, "error"); }
}

function renderKeys(keys) {
  $("#user-keys-table").innerHTML = `
    <thead><tr><th>Type</th><th>Comment</th><th></th></tr></thead>
    <tbody>${keys.map((k) => `
      <tr>
        <td><code>${esc(k.type)}</code>${k.valid ? "" : ' <span class="badge warn">unrecognized</span>'}</td>
        <td>${esc(k.comment || "—")}</td>
        <td><button class="btn btn-small btn-danger" data-key-index="${k.index}">Remove</button></td>
      </tr>`).join("") || "<tr><td colspan='3' class='muted'>No keys installed</td></tr>"}</tbody>`;
}

function closeUserModal() {
  state.editUser = null;
  $("#user-modal").classList.add("hidden");
}

$("#user-modal-close").addEventListener("click", closeUserModal);

$("#user-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/users", {
      method: "POST",
      body: {
        username: $("#new-username").value.trim(),
        full_name: $("#new-full-name").value.trim(),
        password: $("#new-password").value,
        shell: $("#new-shell").value,
        sudo: $("#new-sudo").checked,
        ssh_key: $("#new-ssh-key").value.trim(),
      },
    });
    toast(`User ${$("#new-username").value.trim()} created`, "success");
    $("#user-create-form").reset();
    loadUsers();
  } catch (err) { toast(err.message, "error"); }
});

$("#user-edit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.editUser) return;
  try {
    await api(`/users/${encodeURIComponent(state.editUser)}`, {
      method: "POST",
      body: {
        full_name: $("#edit-full-name").value.trim(),
        shell: $("#edit-shell").value,
        sudo: $("#edit-sudo").checked,
        locked: $("#edit-locked").checked,
      },
    });
    toast("Account updated", "success");
    loadUsers();
    openUser(state.editUser);
  } catch (err) { toast(err.message, "error"); }
});

$("#user-password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.editUser) return;
  try {
    await api(`/users/${encodeURIComponent(state.editUser)}`, {
      method: "POST",
      body: { password: $("#edit-password").value },
    });
    $("#edit-password").value = "";
    toast("Password updated", "success");
  } catch (err) { toast(err.message, "error"); }
});

$("#user-key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.editUser) return;
  try {
    const data = await api(`/users/${encodeURIComponent(state.editUser)}/keys`, {
      method: "POST",
      body: { key: $("#edit-key").value.trim() },
    });
    $("#edit-key").value = "";
    renderKeys(data.keys || []);
    toast("SSH key added", "success");
  } catch (err) { toast(err.message, "error"); }
});

$("#user-keys-table").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-key-index]");
  if (!button || !state.editUser) return;
  try {
    const data = await api(
      `/users/${encodeURIComponent(state.editUser)}/keys/${button.dataset.keyIndex}`,
      { method: "DELETE" },
    );
    renderKeys(data.keys || []);
    toast("SSH key removed", "info");
  } catch (err) { toast(err.message, "error"); }
});

$("#user-delete").addEventListener("click", async () => {
  if (!state.editUser) return;
  const removeHome = $("#delete-remove-home").checked;
  const what = removeHome ? "user and home directory" : "user";
  if (!window.confirm(`Delete ${what} '${state.editUser}'? This cannot be undone.`)) return;
  try {
    await api(`/users/${encodeURIComponent(state.editUser)}?remove_home=${removeHome}`, { method: "DELETE" });
    toast(`User ${state.editUser} deleted`, "success");
    closeUserModal();
    loadUsers();
  } catch (err) { toast(err.message, "error"); }
});

/* --------------------------------------------------------------- software */

$("#software-tabs").addEventListener("click", (event) => {
  const tab = event.target.closest(".tab");
  if (!tab) return;
  $$("#software-tabs .tab").forEach((t) => t.classList.toggle("active", t === tab));
  $$(".tab-panel").forEach((panel) => panel.classList.add("hidden"));
  $(`#tab-${tab.dataset.tab}`).classList.remove("hidden");
});

function pkgRow(pkg, action, kind) {
  return `
    <tr>
      <td><code>${esc(pkg.name)}</code></td>
      <td>${esc(pkg.version || pkg.new || "")}${pkg.old && pkg.new ? ` <span class="muted">(was ${esc(pkg.old)})</span>` : ""}</td>
      <td class="muted">${esc(pkg.description || "")}</td>
      <td><button class="btn btn-small ${kind}" data-pkg="${esc(pkg.name)}" data-action="${action}">${action}</button></td>
    </tr>`;
}

async function loadSoftware() {
  const [upgradable, installed, maintenance] = await Promise.all([
    api("/packages/upgradable"),
    api("/packages/installed"),
    api("/packages/maintenance"),
  ]);
  state.installed = installed.packages || [];
  const cache = maintenance.cache || {};
  const candidates = maintenance.autoremove_candidates || [];
  $("#apt-stats").textContent =
    `Package cache: ${fmtBytes(cache.size_bytes || 0)} in ${cache.files || 0} file(s) · ` +
    `${candidates.length} package(s) can be autoremoved.`;
  $("#apt-autoremove-list").innerHTML = candidates
    .map((name) => `<li><code>${esc(name)}</code></li>`)
    .join("") || "<li class='muted'>Nothing to remove — nice and tidy.</li>";
  $("#pkg-updates-table").innerHTML = `
    <thead><tr><th>Package</th><th>Version</th><th></th><th></th></tr></thead>
    <tbody>${(upgradable.packages || []).map((p) => pkgRow(p, "Install", "btn-primary")).join("")
      || "<tr><td colspan='4' class='muted'>System is up to date</td></tr>"}</tbody>`;
  renderInstalled();
}

function renderInstalled(filter = "") {
  const needle = filter.toLowerCase();
  const rows = state.installed
    .filter((p) => !needle || p.name.toLowerCase().includes(needle))
    .slice(0, 300)
    .map((p) => pkgRow(p, "Remove", "btn-danger"))
    .join("");
  $("#pkg-installed-table").innerHTML = `
    <thead><tr><th>Package</th><th>Version</th><th></th><th></th></tr></thead>
    <tbody>${rows || "<tr><td colspan='4' class='muted'>No packages match</td></tr>"}</tbody>`;
}

$("#pkg-filter").addEventListener("input", (event) => renderInstalled(event.target.value));

$("#search-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const query = $("#search-input").value.trim();
  if (!query) return;
  try {
    const data = await api(`/packages/search?q=${encodeURIComponent(query)}`);
    $("#pkg-search-table").innerHTML = `
      <thead><tr><th>Package</th><th></th><th>Description</th><th></th></tr></thead>
      <tbody>${(data.results || []).map((p) => pkgRow(p, "Install", "btn-primary")).join("")
        || "<tr><td colspan='4' class='muted'>Nothing found</td></tr>"}</tbody>`;
  } catch (err) { toast(err.message, "error"); }
});

$("#view-software").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-pkg]");
  if (!button) return;
  const action = button.dataset.action === "Remove" ? "remove" : "install";
  try {
    const job = await api(`/packages/${action}`, { method: "POST", body: { names: [button.dataset.pkg] } });
    toast(`${button.dataset.action} started for ${button.dataset.pkg}`, "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

$("#pkg-refresh").addEventListener("click", async () => {
  try {
    const job = await api("/packages/update", { method: "POST" });
    toast("Refreshing package lists…", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

async function startMaintenanceJob(path, message) {
  try {
    const job = await api(path, { method: "POST" });
    toast(message, "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
}

$("#pkg-autoremove").addEventListener("click", () =>
  startMaintenanceJob("/packages/autoremove", "Autoremove started"));

$("#pkg-autoclean").addEventListener("click", () =>
  startMaintenanceJob("/packages/autoclean", "Autoclean started"));

$("#pkg-clean").addEventListener("click", () => {
  if (!window.confirm("Delete ALL cached package downloads? They are re-downloaded on demand.")) return;
  startMaintenanceJob("/packages/clean", "Cache cleanup started");
});

$("#pkg-upgrade").addEventListener("click", async () => {
  if (!window.confirm("Upgrade all upgradable packages now?")) return;
  try {
    const job = await api("/packages/upgrade", { method: "POST", body: { full: false } });
    toast("Upgrade started", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

/* ------------------------------------------------------------------- jobs */

async function loadJobs() {
  const data = await api("/jobs");
  const rows = (data.jobs || []).map((job) => `
    <tr class="clickable" data-job="${esc(job.id)}">
      <td><code>${esc(job.id)}</code></td>
      <td>${esc(job.description)}</td>
      <td><span class="badge ${job.status === "succeeded" ? "ok" : job.status === "failed" ? "danger" : job.status === "running" ? "warn" : "muted"}">${esc(job.status)}</span></td>
      <td class="muted">${esc(job.created_at)}</td>
    </tr>`).join("");
  $("#jobs-table").innerHTML = `
    <thead><tr><th>ID</th><th>Description</th><th>Status</th><th>Started</th></tr></thead>
    <tbody>${rows || "<tr><td colspan='4' class='muted'>No jobs yet</td></tr>"}</tbody>`;
  const anyRunning = (data.jobs || []).some((job) => job.status === "running");
  clearInterval(state.jobsTimer);
  if (anyRunning) state.jobsTimer = setInterval(loadJobs, 2500);
}

$("#jobs-table").addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-job]");
  if (row) openJob(row.dataset.job);
});

function openJob(jobId) {
  state.openJob = jobId;
  state.jobLines = 0;
  $("#job-modal-log").textContent = "";
  $("#job-modal-title").textContent = `Job ${jobId}`;
  $("#job-modal").classList.remove("hidden");
  clearInterval(state.jobTimer);
  pollJob();
  state.jobTimer = setInterval(pollJob, 1500);
}

async function pollJob() {
  if (!state.openJob) return;
  try {
    const data = await api(`/jobs/${state.openJob}?after=${state.jobLines}`);
    if (data.lines && data.lines.length) {
      const log = $("#job-modal-log");
      log.textContent += data.lines.join("\n") + "\n";
      log.scrollTop = log.scrollHeight;
      state.jobLines += data.lines.length;
    }
    $("#job-modal-meta").textContent = `${data.job.description} · ${data.job.status}` +
      (data.job.returncode !== null && data.job.returncode !== undefined ? ` · exit ${data.job.returncode}` : "");
    $("#job-modal-cancel").classList.toggle("hidden", data.job.status !== "running");
    if (data.job.status !== "running") {
      clearInterval(state.jobTimer);
      if (state.view === "software") loadSoftware();
      if (state.view === "jobs") loadJobs();
    }
  } catch (err) {
    clearInterval(state.jobTimer);
    toast(err.message, "error");
  }
}

function closeJobModal() {
  clearInterval(state.jobTimer);
  state.openJob = null;
  $("#job-modal").classList.add("hidden");
}

$("#job-modal-close").addEventListener("click", closeJobModal);
$("#job-modal-cancel").addEventListener("click", async () => {
  if (!state.openJob) return;
  try {
    await api(`/jobs/${state.openJob}/cancel`, { method: "POST" });
    toast("Cancellation requested", "info");
    pollJob();
  } catch (err) { toast(err.message, "error"); }
});

/* ------------------------------------------------------------------ audit */

async function loadAudit() {
  const data = await api("/audit");
  const rows = (data.entries || []).map((entry) => `
    <tr>
      <td class="muted">${esc(entry.ts)}</td>
      <td><code>${esc(entry.action)}</code></td>
      <td>${esc(entry.detail)}</td>
      <td><span class="badge ${entry.ok ? "ok" : "danger"}">${entry.ok ? "ok" : "failed"}</span></td>
    </tr>`).join("");
  $("#audit-table").innerHTML = `
    <thead><tr><th>Time</th><th>Action</th><th>Detail</th><th>Result</th></tr></thead>
    <tbody>${rows || "<tr><td colspan='4' class='muted'>Nothing recorded yet</td></tr>"}</tbody>`;
}

/* ------------------------------------------------------------------- init */

if (state.token) hideTokenModal(); else showTokenModal();
loadView();
