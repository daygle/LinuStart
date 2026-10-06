"use strict";

/* Pure helpers (esc, fmtBytes, fmtUptime, niceMax, fmtMetric, mergeLogLines)
   live in util.js, which is loaded first and unit-tested with node --test. */

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
  editKeyIndex: null,
  editUserKeys: [],
  svcEdit: null,
  logFiles: [],
  duJob: null,
  duTimer: null,
  updateChecked: false,
  updateTag: "",
  cronFiles: [],
  cronEdit: null,
  sysctlFiles: [],
  sysctlEdit: null,
};

const $ = (sel, el = document) => el.querySelector(sel);
const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));


function toast(message, kind = "info") {
  const box = document.createElement("div");
  box.className = `toast ${kind === "info" ? "" : kind}`;
  box.textContent = message;
  $("#toasts").appendChild(box);
  setTimeout(() => box.remove(), 5200);
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
    // /health is public, so it would accept any token; ask something guarded.
    await api("/system/overview");
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
  firewall: "Firewall",
  ssh: "SSH Hardening",
  system: "Hostname & Time",
  updates: "Unattended Updates",
  email: "Email",
  users: "Users",
  services: "Services",
  software: "Software",
  storage: "Storage",
  logs: "Logs & Processes",
  cron: "Cron",
  sysctl: "Sysctl",
  terminal: "Terminal",
  jobs: "Jobs",
  audit: "Audit Log",
};

const LOADERS = {
  overview: loadOverview,
  network: loadNetwork,
  firewall: loadFirewall,
  ssh: loadSsh,
  system: loadSystem,
  updates: loadUpdates,
  email: loadMail,
  users: loadUsers,
  services: loadServices,
  software: loadSoftware,
  storage: loadStorage,
  logs: loadLogsView,
  cron: loadCron,
  sysctl: loadSysctl,
  terminal: loadTerminal,
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
  clearInterval(state.metricsTimer);
  stopLogFollow();
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
  $("#server-label").textContent = data.hostname || "-";
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
    const route6 = net.runtime.default_route6;
    $("#overview-addresses").innerHTML = `
      <ul class="list">${rows || "<li class='muted'>No interfaces found</li>"}</ul>
      <div class="muted">Default route: ${route ? `${esc(route.via || "")} via ${esc(route.dev || "")}` : "none"}
        ${route6 ? ` · IPv6: ${esc(route6.via || "")} via ${esc(route6.dev || "")}` : ""}</div>`;
  } catch (err) {
    $("#overview-addresses").innerHTML = `<div class="muted">${esc(err.message)}</div>`;
  }
  await loadMetrics();
  clearInterval(state.metricsTimer);
  state.metricsTimer = setInterval(() => { if (state.view === "overview") loadMetrics(); }, 60000);
}

/* ---------------------------------------------------------------- metrics */

// Small multiples: one single-series chart per metric (different units, so
// never a shared or second axis). Line 2px in the accent, a 10% area wash,
// hairline grid, the latest value labelled at the line's end, the alert
// limit as a quiet reference line, and a crosshair tooltip on hover/focus.
const METRIC_CHARTS = [
  { key: "cpu", title: "CPU", unit: "%", max: 100 },
  { key: "mem", title: "Memory", unit: "%", max: 100 },
  { key: "disk", title: "Disk /", unit: "%", max: 100 },
  { key: "load", title: "Load average (1 min)", unit: "", max: null },
];
const SVG_NS = "http://www.w3.org/2000/svg";

function svgEl(tag, attrs, parent) {
  const el = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs || {}).forEach(([k, v]) => el.setAttribute(k, String(v)));
  if (parent) parent.appendChild(el);
  return el;
}



function fmtClock(t) {
  return new Date(t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function renderMetricChart(box, spec, samples, limit, interval) {
  box.textContent = "";
  const title = document.createElement("h3");
  title.textContent = spec.title;
  box.appendChild(title);
  const points = samples.filter((s) => typeof s[spec.key] === "number");
  const width = Math.max(200, Math.round(box.getBoundingClientRect().width) || 300);
  const height = 130;
  const m = { left: 30, right: 52, top: 10, bottom: 18 };
  const svg = svgEl("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", tabindex: 0,
    "aria-label": `${spec.title} over the last 24 hours` }, box);
  if (!points.length) {
    const t = svgEl("text", { x: width / 2, y: height / 2, "text-anchor": "middle", class: "tick" }, svg);
    t.textContent = "Collecting - the first points appear within a minute";
    return;
  }
  const t1 = points[points.length - 1].t;
  const t0 = Math.min(points[0].t, t1 - 3600);
  const peak = Math.max(...points.map((p) => p[spec.key]), limit || 0);
  const yMax = spec.max || niceMax(peak * 1.1);
  const x = (t) => m.left + ((t - t0) / Math.max(1, t1 - t0)) * (width - m.left - m.right);
  const y = (v) => m.top + (1 - Math.min(v, yMax) / yMax) * (height - m.top - m.bottom);
  const grid = getComputedStyle(document.documentElement);
  const border = grid.getPropertyValue("--border").trim() || "#e2e8f0";
  const accent = grid.getPropertyValue("--accent").trim() || "#2563eb";
  const muted = grid.getPropertyValue("--muted").trim() || "#64748b";
  const panel = grid.getPropertyValue("--panel").trim() || "#ffffff";
  [0, yMax / 2, yMax].forEach((v) => {
    svgEl("line", { x1: m.left, x2: width - m.right, y1: y(v), y2: y(v), stroke: border, "stroke-width": 1 }, svg);
    const label = svgEl("text", { x: m.left - 6, y: y(v) + 3, "text-anchor": "end", class: "tick" }, svg);
    label.textContent = spec.unit === "%" ? `${v}` : `${+v.toFixed(2)}`;
  });
  [[t0, "start"], [t1, "end"]].forEach(([t, anchor]) => {
    const label = svgEl("text", { x: x(t), y: height - 4, "text-anchor": anchor, class: "tick" }, svg);
    label.textContent = fmtClock(t);
  });
  if (limit && limit <= yMax) {
    svgEl("line", { x1: m.left, x2: width - m.right, y1: y(limit), y2: y(limit), stroke: muted, "stroke-width": 1 }, svg);
    const ref = svgEl("text", { x: m.left + 4, y: y(limit) - 4, class: "ref-label" }, svg);
    ref.textContent = `alert ${fmtMetric(limit, spec.unit)}`;
  }
  // a gap of more than two intervals (panel stopped) breaks the line
  const segments = [];
  points.forEach((p, i) => {
    if (!i || p.t - points[i - 1].t > interval * 2.5) segments.push([]);
    segments[segments.length - 1].push(p);
  });
  segments.forEach((seg) => {
    const line = seg.map((p, i) => `${i ? "L" : "M"}${x(p.t).toFixed(1)},${y(p[spec.key]).toFixed(1)}`).join("");
    if (seg.length > 1) {
      const base = y(0).toFixed(1);
      svgEl("path", { d: `${line}L${x(seg[seg.length - 1].t).toFixed(1)},${base}L${x(seg[0].t).toFixed(1)},${base}Z`,
        fill: accent, "fill-opacity": 0.1 }, svg);
    }
    svgEl("path", { d: line, fill: "none", stroke: accent, "stroke-width": 2,
      "stroke-linejoin": "round", "stroke-linecap": "round" }, svg);
  });
  const last = points[points.length - 1];
  svgEl("circle", { cx: x(last.t), cy: y(last[spec.key]), r: 4, fill: accent, stroke: panel, "stroke-width": 2 }, svg);
  const end = svgEl("text", { x: x(last.t) + 8, y: y(last[spec.key]) + 4, class: "end-label" }, svg);
  end.textContent = fmtMetric(last[spec.key], spec.unit);

  // crosshair + tooltip; the whole plot is the hit target
  const cross = svgEl("line", { y1: m.top, y2: height - m.bottom, stroke: muted, "stroke-width": 1, visibility: "hidden" }, svg);
  const dot = svgEl("circle", { r: 4, fill: accent, stroke: panel, "stroke-width": 2, visibility: "hidden" }, svg);
  const tip = document.createElement("div");
  tip.className = "chart-tip hidden";
  const tipValue = document.createElement("strong");
  const tipTime = document.createElement("span");
  tip.append(tipValue, tipTime);
  box.appendChild(tip);
  let focusIndex = points.length - 1;
  const show = (index) => {
    const p = points[Math.max(0, Math.min(points.length - 1, index))];
    focusIndex = points.indexOf(p);
    const px = x(p.t);
    cross.setAttribute("x1", px); cross.setAttribute("x2", px); cross.setAttribute("visibility", "visible");
    dot.setAttribute("cx", px); dot.setAttribute("cy", y(p[spec.key])); dot.setAttribute("visibility", "visible");
    tipValue.textContent = fmtMetric(p[spec.key], spec.unit);
    tipTime.textContent = fmtClock(p.t);
    tip.classList.remove("hidden");
    const scale = svg.getBoundingClientRect().width / width || 1;
    const left = Math.min(px * scale + 10, svg.getBoundingClientRect().width - tip.offsetWidth - 4);
    tip.style.left = `${Math.max(0, left)}px`;
    tip.style.top = `${title.offsetHeight + 4}px`;
  };
  const hide = () => {
    cross.setAttribute("visibility", "hidden"); dot.setAttribute("visibility", "hidden");
    tip.classList.add("hidden");
  };
  const hit = svgEl("rect", { x: m.left, y: 0, width: width - m.left - m.right, height, fill: "transparent" }, svg);
  hit.addEventListener("pointermove", (event) => {
    const rect = svg.getBoundingClientRect();
    const t = t0 + ((event.clientX - rect.left) * (width / rect.width) - m.left) / (width - m.left - m.right) * (t1 - t0);
    let best = 0;
    points.forEach((p, i) => { if (Math.abs(p.t - t) < Math.abs(points[best].t - t)) best = i; });
    show(best);
  });
  hit.addEventListener("pointerleave", hide);
  svg.addEventListener("focus", () => show(focusIndex));
  svg.addEventListener("blur", hide);
  svg.addEventListener("keydown", (event) => {
    if (event.key === "ArrowLeft") { show(focusIndex - 1); event.preventDefault(); }
    if (event.key === "ArrowRight") { show(focusIndex + 1); event.preventDefault(); }
  });
}

function renderMetricTable(samples) {
  // one row per 10 minutes keeps the table readable; values match the charts
  const rows = samples.filter((s, i) => i === samples.length - 1 || s.t % 600 < 60).reverse().map((s) => `
    <tr><td>${esc(new Date(s.t * 1000).toLocaleString())}</td>
      ${METRIC_CHARTS.map((c) => `<td class="num">${esc(fmtMetric(s[c.key], c.unit))}</td>`).join("")}</tr>`).join("");
  $("#metrics-table").innerHTML = `
    <thead><tr><th>Time</th>${METRIC_CHARTS.map((c) => `<th>${esc(c.title)}</th>`).join("")}</tr></thead>
    <tbody>${rows || "<tr><td colspan='5' class='muted'>No samples yet</td></tr>"}</tbody>`;
}

function renderAlerts(alerts, recipient) {
  const cfg = alerts.config || {};
  $("#alert-enabled").checked = !!cfg.enabled;
  $("#alert-cpu").value = cfg.cpu;
  $("#alert-mem").value = cfg.mem;
  $("#alert-disk").value = cfg.disk;
  $("#alert-load").value = cfg.load_per_cpu;
  $("#alert-sustain").value = cfg.sustain_minutes;
  $("#alert-cooldown").value = cfg.cooldown_minutes;
  $("#alert-recipient").value = cfg.recipient || "";
  $("#alert-recipient").placeholder = recipient && !cfg.recipient
    ? `${recipient} (from the Email page)` : "ops@example.com or root";
  const status = $("#alerts-status");
  const active = alerts.active || [];
  if (!cfg.enabled) { status.className = "badge muted"; status.textContent = "off"; }
  else if (active.length) {
    status.className = "badge warn";
    status.textContent = `⚠ alerting: ${active.map((k) => (METRIC_CHARTS.find((c) => c.key === k) || {}).title || k).join(", ")}`;
  } else { status.className = "badge ok"; status.textContent = "✓ on, all within limits"; }
}

async function loadMetrics() {
  try {
    const data = await api("/metrics");
    state.metricsData = data;
    renderMetrics(data);
  } catch (err) { $("#metrics-note").textContent = err.message; }
}

function renderMetrics(data) {
  const samples = data.samples || [];
  const thresholds = (data.alerts && data.alerts.thresholds) || {};
  const enabled = data.alerts && data.alerts.config && data.alerts.config.enabled;
  const container = $("#metrics-charts");
  container.textContent = "";
  // lay every box out first, then measure: a box measured before its
  // siblings exist gets the whole row's width and renders at the wrong scale
  const boxes = METRIC_CHARTS.map(() => {
    const box = document.createElement("div");
    box.className = "chart";
    container.appendChild(box);
    return box;
  });
  METRIC_CHARTS.forEach((spec, i) => {
    renderMetricChart(boxes[i], spec, samples, enabled ? thresholds[spec.key] : null, data.interval || 60);
  });
  $("#metrics-note").textContent = `sampled every ${data.interval || 60}s · ${data.cpus} CPU(s)`;
  renderMetricTable(samples);
  renderAlerts(data.alerts || {}, data.recipient);
}

window.addEventListener("resize", () => {
  clearTimeout(state.metricsResize);
  state.metricsResize = setTimeout(() => { if (state.view === "overview" && state.metricsData) renderMetrics(state.metricsData); }, 200);
});

$("#alerts-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = {
    enabled: $("#alert-enabled").checked,
    cpu: Number($("#alert-cpu").value),
    mem: Number($("#alert-mem").value),
    disk: Number($("#alert-disk").value),
    load_per_cpu: Number($("#alert-load").value),
    sustain_minutes: Number($("#alert-sustain").value),
    cooldown_minutes: Number($("#alert-cooldown").value),
    recipient: $("#alert-recipient").value.trim(),
  };
  try {
    await api("/metrics/alerts", { method: "POST", body });
    toast("Alert settings saved", "success");
    loadMetrics();
  } catch (err) { toast(err.message, "error"); }
});

$("#alert-test").addEventListener("click", async () => {
  try {
    await api("/metrics/alerts/test", { method: "POST" });
    toast("Test alert sent", "success");
  } catch (err) { toast(err.message, "error"); }
});

/* ---------------------------------------------------------------- network */

function renderResolver(resolver) {
  const box = $("#net-resolver");
  if (!resolver) {
    box.innerHTML = "<p class='muted'>resolver status unavailable</p>";
    return;
  }
  const servers = (resolver.nameservers || []).length
    ? resolver.nameservers.map((n) => `<code>${esc(n)}</code>`).join(", ")
    : '<span class="badge warn">no nameservers configured</span>';
  const badge = resolver.dns_setting_applies
    ? '<span class="badge ok">panel DNS applies</span>'
    : '<span class="badge warn">panel DNS not applied</span>';
  const notes = (resolver.warnings || [])
    .map((w) => `<p class="muted"><span class="badge warn">note</span> ${esc(w)}</p>`)
    .join("");
  const generated = resolver.generated_by && resolver.generated_by !== resolver.manager
    ? ` (file says: ${esc(resolver.generated_by)})`
    : "";
  const fix = resolver.can_install_resolvconf
    ? `<p><button class="btn" id="net-resolvconf-install">Install resolvconf</button>
       <span class="muted">makes the DNS servers saved below apply, now and at boot</span></p>`
    : "";
  box.innerHTML = `
    <p><span class="badge">${esc(resolver.manager)}</span>${generated} ${badge}</p>
    <p class="muted">${esc(resolver.path || "/etc/resolv.conf")} → ${servers}</p>
    ${notes}${fix}`;
  const button = $("#net-resolvconf-install");
  if (button) button.addEventListener("click", installResolvconf);
}

async function installResolvconf() {
  if (!window.confirm(
    "Install resolvconf? It takes over /etc/resolv.conf and fills it from the DNS servers " +
    "configured on each interface. If that leaves no nameserver, the current file is put back.",
  )) return;
  try {
    const job = await api("/network/resolvconf", { method: "POST" });
    toast("Installing resolvconf…", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
}

async function loadNetwork() {
  const data = await api("/network");
  $("#net-backend").textContent = `backend: ${data.backend}`;
  $("#net-source").textContent = (data.config && data.config.source) || "";
  renderResolver(data.resolver);
  const runtimeRows = (data.runtime.interfaces || []).map((iface) => `
    <tr>
      <td><code>${esc(iface.name)}</code></td>
      <td><span class="badge ${iface.state === "up" ? "ok" : "muted"}">${esc(iface.state)}</span></td>
      <td>${esc([...(iface.addresses || []), ...(iface.addresses6 || [])].join(", "))}</td>
      <td class="muted">${esc(iface.mac || "")}</td>
    </tr>`).join("");
  $("#net-runtime-table").innerHTML = `
    <thead><tr><th>Interface</th><th>State</th><th>Addresses</th><th>MAC</th></tr></thead>
    <tbody>${runtimeRows || "<tr><td colspan='4' class='muted'>No interfaces found</td></tr>"}</tbody>`;

  const cards = (data.config.interfaces || []).map((iface) => {
    const method = iface.method || "dhcp";
    const stanzas = Number(iface.stanza_count || 1);
    const duplicated = stanzas > 1
      ? `<p class="muted"><span class="badge warn">${stanzas} stanzas</span> this interface is
         configured ${stanzas} times across /etc/network/interfaces and the files it sources. ifupdown applies all of them,
         so a leftover DHCP block here still runs alongside the settings below - saving this
         interface collapses them into one.</p>`
      : "";
    const dhcpElsewhere = (iface.dhcp_sources || []).length
      ? `<p class="muted"><span class="badge warn">DHCP elsewhere</span> netplan merges every
         file in /etc/netplan, so DHCP set in
         ${iface.dhcp_sources.map((s) => `<code>${esc(String(s).split("/").pop())}</code>`).join(", ")}
         still applies to this interface. Saving this interface switches DHCP off in every
         file that has it.</p>`
      : "";
    const dnsNoop = data.resolver && !data.resolver.dns_setting_applies
      ? `<p class="muted"><span class="badge warn">DNS no-op</span> the DNS servers entered here
         are not applied on this system${(data.resolver.warnings || []).length ? ` - ${esc(data.resolver.warnings[0])}` : ""}.</p>`
      : "";
    const v6 = iface.ipv6 || null;
    const v6method = v6 ? v6.method : "";
    const kind = iface.kind && iface.kind !== "ethernets" && iface.kind !== "ethernet"
      ? ` <span class="badge muted">${esc(String(iface.kind).replace(/s$/, ""))}</span>` : "";
    const inactive = iface.active === false ? ' <span class="badge warn">inactive</span>' : "";
    return `
    <div class="card">
      <h2>${esc(iface.name)} <span class="badge">${esc(method)}</span>${kind}${inactive}</h2>
      ${duplicated}
      ${dhcpElsewhere}
      ${dnsNoop}
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
          <input type="text" name="dns" value="${esc((iface.dns || []).join(", "))}" placeholder="1.1.1.1, 2606:4700:4700::1111">
        </label>
        <label>IPv6
          <select name="ipv6_method">
            <option value="" selected>Leave unchanged${v6method ? ` (currently ${esc(v6method)})` : ""}</option>
            <option value="none">Not configured</option>
            <option value="auto">Automatic (SLAAC)</option>
            <option value="dhcp">DHCPv6</option>
            <option value="static">Static</option>
          </select>
        </label>
        <label>IPv6 address (CIDR)
          <input type="text" name="ipv6_address" value="${esc((v6 && v6.address) || "")}" placeholder="2001:db8::10/64">
        </label>
        <label>IPv6 gateway
          <input type="text" name="ipv6_gateway" value="${esc((v6 && v6.gateway) || "")}" placeholder="fe80::1">
        </label>
        <button class="btn btn-primary" type="submit">Apply (with 90s Auto-Revert)</button>
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
      if (el.ipv6_method.value) {
        body.ipv6_method = el.ipv6_method.value;
        body.ipv6_address = el.ipv6_address.value.trim() || null;
        body.ipv6_gateway = el.ipv6_gateway.value.trim() || null;
      }
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
    `Changes applied (${session.label || "system"}). Confirm to keep them - otherwise they revert automatically.`;
  let left = session.seconds_left;
  const tick = () => {
    $("#revert-countdown").textContent = `revert in ${left}s`;
    left -= 1;
    if (left < 0) { hideRevertBar(); loadView(); }
  };
  tick();
  state.sessionTimer = setInterval(tick, 1000);
}

$("#revert-confirm").addEventListener("click", async () => {
  if (!state.session) return;
  try {
    await api(`/sessions/${state.session.id}/confirm`, { method: "POST" });
    toast("Configuration saved", "success");
  } catch (err) {
    toast(err.message, "error");
  }
  hideRevertBar();
});

$("#revert-discard").addEventListener("click", async () => {
  if (!state.session) return;
  try {
    await api(`/sessions/${state.session.id}/revert`, { method: "POST" });
    toast("Changes reverted", "info");
  } catch (err) {
    toast(err.message, "error");
  }
  hideRevertBar();
  loadView();
});

/* ----------------------------------------------------------------- system */

async function loadSystem() {
  // Power status is independent of the hostname/timezone reads, so it loads on
  // its own: a failing timedatectl/systemctl must not blank the power controls.
  loadPowerStatus();
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

/* ------------------------------------------------------------------- power */

async function loadPowerStatus() {
  try {
    renderPower(await api("/power"));
  } catch (err) {
    if (err.message === "Authentication required") throw err;
    $("#power-status").textContent = `Could not read power status: ${err.message}`;
    $("#power-reboot").disabled = true;
    $("#power-shutdown").disabled = true;
  }
}

function renderPower(data) {
  const status = $("#power-status");
  const cancel = $("#power-cancel");
  const pending = !!data.pending;
  cancel.classList.toggle("hidden", !pending);
  $("#power-reboot").disabled = pending;
  $("#power-shutdown").disabled = pending;
  if (pending) {
    const action = data.action === "shutdown" ? "Shutdown" : "Reboot";
    status.textContent = `${action} is pending (unit ${data.unit}). The server goes away when the countdown ends.`;
    cancel.dataset.action = data.action;
  } else {
    status.textContent = "Nothing scheduled. This server is not going to reboot or shut down on its own.";
  }
}

async function schedulePower(action) {
  const isShutdown = action === "shutdown";
  const verb = isShutdown ? "Shut down" : "Reboot";
  const outcome = isShutdown ? "shut down" : "rebooted";
  const delay = $("#power-delay").value;
  if (!window.confirm(
    `${verb} this server?\n\nThe panel and every service on the machine stop. Make sure you have console or physical access in case it does not come back.`
  )) return;
  if (!window.confirm(`${verb} in ${delay} seconds?\n\nYou can cancel from this page until the countdown ends.`)) return;
  try {
    await api("/power", { method: "POST", body: { action, delay: Number(delay), confirm: true } });
    toast(`${verb} scheduled — the server will be ${outcome} shortly`, "success");
    loadPowerStatus();
  } catch (err) { toast(err.message, "error"); }
}

$("#power-reboot").addEventListener("click", () => schedulePower("reboot"));
$("#power-shutdown").addEventListener("click", () => schedulePower("shutdown"));

$("#power-cancel").addEventListener("click", async () => {
  const action = $("#power-cancel").dataset.action;
  if (!action) return;
  if (!window.confirm("Cancel the pending reboot or shutdown?")) return;
  try {
    const result = await api("/power/cancel", { method: "POST", body: { action, confirm: true } });
    toast(result.cancelled ? `Pending ${action} cancelled` : "Nothing was pending", "success");
    loadPowerStatus();
  } catch (err) { toast(err.message, "error"); }
});

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
  $("#uu-download").checked = data.download_upgradeable_packages !== false;
  $("#uu-autoclean").value = String(data.autoclean_interval ?? "0");
  $("#uu-reboot").checked = !!data.auto_reboot;
  $("#uu-reboot-time").value = data.auto_reboot_time || "";
  $("#uu-reboot-users").checked = data.auto_reboot_withusers !== false;
  $("#uu-remove-unused").checked = data.remove_unused !== false;
  $("#uu-remove-new-deps").checked = data.remove_new_unused_dependencies !== false;
  $("#uu-remove-deps").checked = !!data.remove_unused_dependencies;
  $("#uu-fix-dpkg").checked = data.auto_fix_interrupted_dpkg !== false;
  $("#uu-report-to").value = data.report_to || "";
  $("#uu-report-mode").value = data.report_mode || "only-on-error";
  $("#uu-origins-style").value = data.origins_style || "pattern";
  $("#uu-origins").value = (data.origins || []).join("\n");
  $("#uu-blacklist").value = (data.package_blacklist || []).join("\n");
  $("#uu-files").innerHTML = Object.values(data.files || {})
    .map((f) => `<li><code>${esc(f)}</code></li>`).join("");
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
        download_upgradeable_packages: $("#uu-download").checked,
        autoclean_interval: $("#uu-autoclean").value.trim(),
        auto_reboot: $("#uu-reboot").checked,
        auto_reboot_time: $("#uu-reboot-time").value.trim(),
        auto_reboot_withusers: $("#uu-reboot-users").checked,
        remove_unused: $("#uu-remove-unused").checked,
        remove_new_unused_dependencies: $("#uu-remove-new-deps").checked,
        remove_unused_dependencies: $("#uu-remove-deps").checked,
        auto_fix_interrupted_dpkg: $("#uu-fix-dpkg").checked,
        report_to: $("#uu-report-to").value.trim(),
        report_mode: $("#uu-report-mode").value,
      },
    });
    toast("Unattended updates configuration saved", "success");
    loadUpdates();
  } catch (err) { toast(err.message, "error"); }
});

$("#uu-origins-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const lines = (value) => value.split("\n").map((s) => s.trim()).filter(Boolean);
  try {
    await api("/updates", {
      method: "POST",
      body: {
        origins_style: $("#uu-origins-style").value,
        origins: lines($("#uu-origins").value),
        package_blacklist: lines($("#uu-blacklist").value),
      },
    });
    toast("Upgrade origins saved", "success");
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

/* ------------------------------------------------------------------- cron */

async function loadCron() {
  const data = await api("/cron");
  state.cronFiles = data.files || [];
  state.cronSchedules = data.schedules || [];
  const kindLabels = {
    system: "system crontab",
    "cron.d": "cron.d drop-in",
    user: "user crontab",
  };
  $("#cron-summary").textContent =
    `${data.jobs || 0} job(s) in ${state.cronFiles.length} file(s)`;
  $("#cron-files").innerHTML = state.cronFiles.map((file) => {
    if (file.kind === "error") {
      return `<div class="card"><h2><code>${esc(file.path)}</code></h2>`
        + `<p class="muted">This file could not be read: ${esc(file.detail || "")}</p></div>`;
    }
    const rows = (file.entries || []).map((entry) => `
      <tr${entry.enabled ? "" : ' class="muted"'}>
        <td><code>${esc(entry.schedule)}</code>${entry.enabled ? "" : " (disabled)"}${entry.valid ? "" : ' <span class="badge">invalid</span>'}</td>
        <td>${esc(entry.user || file.owner)}</td>
        <td><code>${esc(entry.command)}</code></td>
        <td>
          <button class="btn btn-small" type="button" data-cron-edit="${esc(file.path)}" data-cron-index="${entry.index}">Edit</button>
          <button class="btn btn-small btn-danger" type="button" data-cron-delete="${esc(file.path)}" data-cron-index="${entry.index}">Delete</button>
        </td>
      </tr>`).join("");
    return `
      <div class="card">
        <h2><code>${esc(file.path)}</code> <span class="badge">${kindLabels[file.kind] || file.kind}</span></h2>
        ${rows
          ? `<table class="table"><thead><tr><th>Schedule</th><th>Run As</th><th>Command</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
          : '<p class="muted">No jobs in this file.</p>'}
        <div class="form-row">
          <button class="btn" type="button" data-cron-add="${esc(file.path)}">Add Job</button>
          ${file.kind === "system" ? "" : `<button class="btn btn-danger" type="button" data-cron-deletefile="${esc(file.path)}">Delete File</button>`}
        </div>
      </div>`;
  }).join("") || '<div class="card"><p class="muted">No cron files found.</p></div>';
  $("#cron-file").innerHTML = state.cronFiles
    .filter((file) => file.kind !== "error")
    .map((file) => `<option value="${esc(file.path)}">${esc(file.path)}</option>`).join("");
}

function openCronModal(path, index) {
  const file = (state.cronFiles || []).find((item) => item.path === path);
  const entry = index >= 0
    ? ((file && file.entries) || []).find((item) => item.index === index) || null
    : null;
  state.cronEdit = { path, index: entry ? entry.index : -1, raw: entry ? entry.raw : "" };
  $("#cron-modal-title").textContent = entry ? "Edit Job" : "Add Job";
  $("#cron-modal-path").textContent = entry ? path : "Adding a new job";
  $("#cron-target-row").classList.toggle("hidden", !!entry);
  $("#cron-file").value = path;
  $("#cron-schedule").value = entry ? entry.schedule : "*/5 * * * *";
  $("#cron-command").value = entry ? entry.command : "";
  $("#cron-user").value = entry ? entry.user : (file ? file.owner : "root");
  // a user crontab has no user column; its owner is implied
  $("#cron-user").disabled = !!(file && file.kind === "user");
  $("#cron-enabled").checked = entry ? !!entry.enabled : true;
  $("#cron-modal-delete").classList.toggle("hidden", !entry);
  $("#cron-schedules-hint").innerHTML = (state.cronSchedules || [])
    .map((preset) => `<button class="btn btn-small" type="button" data-cron-preset="${esc(preset)}">${esc(preset)}</button>`)
    .join(" ");
  $("#cron-modal").classList.remove("hidden");
  $("#cron-schedule").focus();
}

function closeCronModal() {
  $("#cron-modal").classList.add("hidden");
  state.cronEdit = null;
}

$("#cron-refresh").addEventListener("click", () => loadCron());
$("#cron-add").addEventListener("click", () => openCronModal($("#cron-file").value, -1));
$("#cron-modal-close").addEventListener("click", closeCronModal);
$("#cron-modal-cancel").addEventListener("click", closeCronModal);

$("#cron-schedules-hint").addEventListener("click", (event) => {
  const preset = event.target.closest("[data-cron-preset]");
  if (preset) $("#cron-schedule").value = preset.dataset.cronPreset;
});

$("#view-cron").addEventListener("click", async (event) => {
  const edit = event.target.closest("[data-cron-edit]");
  if (edit) return openCronModal(edit.dataset.cronEdit, Number(edit.dataset.cronIndex));
  const add = event.target.closest("[data-cron-add]");
  if (add) return openCronModal(add.dataset.cronAdd, -1);

  const drop = event.target.closest("[data-cron-delete]");
  if (drop) {
    const entry = ((state.cronFiles.find((f) => f.path === drop.dataset.cronDelete) || {}).entries || [])
      .find((item) => item.index === Number(drop.dataset.cronIndex));
    if (!window.confirm(`Delete this job?\n\n${entry ? entry.schedule + " " + entry.command : ""}`)) return;
    try {
      await api("/cron/delete", {
        method: "POST",
        body: { path: drop.dataset.cronDelete, index: Number(drop.dataset.cronIndex), expected: entry ? entry.raw : "" },
      });
      toast("Cron job deleted", "success");
      loadCron();
    } catch (err) { toast(err.message, "error"); }
    return;
  }

  const dropFile = event.target.closest("[data-cron-deletefile]");
  if (dropFile) {
    const path = dropFile.dataset.cronDeletefile;
    if (!window.confirm(`Delete ${path} and every job in it? This cannot be undone.`)) return;
    try {
      await api("/cron/delete-file", { method: "POST", body: { path } });
      toast("Cron file deleted", "success");
      loadCron();
    } catch (err) { toast(err.message, "error"); }
  }
});

$("#cron-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const edit = state.cronEdit || { path: $("#cron-file").value, index: -1, raw: "" };
  try {
    await api("/cron/entry", {
      method: "POST",
      body: {
        path: edit.path || $("#cron-file").value,
        index: edit.index,
        schedule: $("#cron-schedule").value.trim(),
        command: $("#cron-command").value.trim(),
        user: $("#cron-user").value.trim(),
        enabled: $("#cron-enabled").checked,
        expected: edit.raw,
      },
    });
    toast(edit.index < 0 ? "Cron job added" : "Cron job saved", "success");
    closeCronModal();
    loadCron();
  } catch (err) { toast(err.message, "error"); }
});

$("#cron-modal-delete").addEventListener("click", async () => {
  const edit = state.cronEdit;
  if (!edit || edit.index < 0) return;
  if (!window.confirm("Delete this cron job?")) return;
  try {
    await api("/cron/delete", { method: "POST", body: { path: edit.path, index: edit.index, expected: edit.raw } });
    toast("Cron job deleted", "success");
    closeCronModal();
    loadCron();
  } catch (err) { toast(err.message, "error"); }
});

/* ----------------------------------------------------------------- sysctl */

async function loadSysctl() {
  const data = await api("/sysctl");
  state.sysctlFiles = data.files || [];
  $("#sysctl-summary").textContent =
    `${data.settings || 0} setting(s) in ${state.sysctlFiles.length} file(s)`;
  $("#sysctl-files").innerHTML = state.sysctlFiles.map((file) => {
    if (file.kind === "error") {
      return `<div class="card"><h2><code>${esc(file.path)}</code></h2>`
        + `<p class="muted">This file could not be read: ${esc(file.detail || "")}</p></div>`;
    }
    const rows = (file.entries || []).map((entry) => `
      <tr${entry.valid ? "" : ' class="muted"'}>
        <td><code>${esc(entry.key)}</code></td>
        <td><code>${esc(entry.value)}</code></td>
        <td>${entry.runtime === null || entry.runtime === undefined
          ? '<span class="muted">-</span>'
          : `<code>${esc(entry.runtime)}</code>${entry.changed ? ' <span class="badge">pending</span>' : ""}`}</td>
        <td>
          <button class="btn btn-small" type="button" data-sysctl-edit="${esc(file.path)}" data-sysctl-index="${entry.index}">Edit</button>
          <button class="btn btn-small btn-danger" type="button" data-sysctl-delete="${esc(file.path)}" data-sysctl-index="${entry.index}">Delete</button>
        </td>
      </tr>`).join("");
    const label = file.kind === "main" ? "applied last" : "drop-in";
    return `
      <div class="card">
        <h2><code>${esc(file.path)}</code> <span class="badge">${label}</span></h2>
        ${rows
          ? `<table class="table"><thead><tr><th>Parameter</th><th>Configured</th><th>Runtime</th><th></th></tr></thead><tbody>${rows}</tbody></table>`
          : '<p class="muted">No settings in this file.</p>'}
        <div class="form-row">
          <button class="btn" type="button" data-sysctl-add="${esc(file.path)}">Add Setting</button>
          ${file.kind === "main" ? "" : `<button class="btn btn-danger" type="button" data-sysctl-deletefile="${esc(file.path)}">Delete File</button>`}
        </div>
      </div>`;
  }).join("") || '<div class="card"><p class="muted">No sysctl configuration files found.</p></div>';
  $("#sysctl-file").innerHTML = [
    `<option value="${esc(data.default_file)}">${esc(data.default_file)} (new)</option>`,
    ...state.sysctlFiles
      .filter((file) => file.kind !== "error")
      .map((file) => `<option value="${esc(file.path)}">${esc(file.path)}</option>`),
  ].join("");
}

function openSysctlModal(path, index) {
  const file = (state.sysctlFiles || []).find((item) => item.path === path);
  const entry = index >= 0
    ? ((file && file.entries) || []).find((item) => item.index === index) || null
    : null;
  state.sysctlEdit = { path, index: entry ? entry.index : -1, raw: entry ? entry.raw : "" };
  $("#sysctl-modal-title").textContent = entry ? "Edit Setting" : "Add Setting";
  $("#sysctl-modal-path").textContent = entry ? path : "Adding a new setting";
  $("#sysctl-target-row").classList.toggle("hidden", !!entry);
  $("#sysctl-file").value = path;
  $("#sysctl-key").value = entry ? entry.key : "";
  $("#sysctl-value").value = entry ? entry.value : "";
  const runtime = entry ? entry.runtime : null;
  $("#sysctl-runtime-hint").textContent = runtime === null || runtime === undefined
    ? ""
    : `The kernel is currently using ${runtime} for this parameter.`;
  $("#sysctl-modal-delete").classList.toggle("hidden", !entry);
  $("#sysctl-modal").classList.remove("hidden");
  $("#sysctl-key").focus();
}

function closeSysctlModal() {
  $("#sysctl-modal").classList.add("hidden");
  state.sysctlEdit = null;
}

$("#sysctl-refresh").addEventListener("click", () => loadSysctl());

$("#sysctl-apply").addEventListener("click", async () => {
  try {
    await api("/sysctl/apply", { method: "POST" });
    toast("All sysctl settings applied", "success");
    loadSysctl();
  } catch (err) { toast(err.message, "error"); }
});

$("#sysctl-add").addEventListener("click", () => openSysctlModal($("#sysctl-file").value, -1));
$("#sysctl-modal-close").addEventListener("click", closeSysctlModal);
$("#sysctl-modal-cancel").addEventListener("click", closeSysctlModal);

$("#view-sysctl").addEventListener("click", async (event) => {
  const edit = event.target.closest("[data-sysctl-edit]");
  if (edit) return openSysctlModal(edit.dataset.sysctlEdit, Number(edit.dataset.sysctlIndex));
  const add = event.target.closest("[data-sysctl-add]");
  if (add) return openSysctlModal(add.dataset.sysctlAdd, -1);

  const drop = event.target.closest("[data-sysctl-delete]");
  if (drop) {
    const file = state.sysctlFiles.find((f) => f.path === drop.dataset.sysctlDelete) || {};
    const entry = (file.entries || []).find((item) => item.index === Number(drop.dataset.sysctlIndex));
    if (!window.confirm(`Remove this setting?\n\n${entry ? `${entry.key} = ${entry.value}` : ""}`)) return;
    try {
      await api("/sysctl/delete", {
        method: "POST",
        body: { path: drop.dataset.sysctlDelete, index: Number(drop.dataset.sysctlIndex), expected: entry ? entry.raw : "" },
      });
      toast("Setting removed", "success");
      loadSysctl();
    } catch (err) { toast(err.message, "error"); }
    return;
  }

  const dropFile = event.target.closest("[data-sysctl-deletefile]");
  if (dropFile) {
    const path = dropFile.dataset.sysctlDeletefile;
    if (!window.confirm(`Delete ${path}? Settings from other files will still apply.`)) return;
    try {
      await api("/sysctl/delete-file", { method: "POST", body: { path } });
      toast("File deleted", "success");
      loadSysctl();
    } catch (err) { toast(err.message, "error"); }
  }
});

$("#sysctl-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const edit = state.sysctlEdit || { path: $("#sysctl-file").value, index: -1, raw: "" };
  try {
    await api("/sysctl/entry", {
      method: "POST",
      body: {
        path: edit.path || $("#sysctl-file").value,
        index: edit.index,
        key: $("#sysctl-key").value.trim(),
        value: $("#sysctl-value").value.trim(),
        expected: edit.raw,
      },
    });
    toast(edit.index < 0 ? "Setting added and applied" : "Setting saved and applied", "success");
    closeSysctlModal();
    loadSysctl();
  } catch (err) { toast(err.message, "error"); }
});

$("#sysctl-modal-delete").addEventListener("click", async () => {
  const edit = state.sysctlEdit;
  if (!edit || edit.index < 0) return;
  if (!window.confirm("Remove this setting and re-apply?")) return;
  try {
    await api("/sysctl/delete", { method: "POST", body: { path: edit.path, index: edit.index, expected: edit.raw } });
    toast("Setting removed", "success");
    closeSysctlModal();
    loadSysctl();
  } catch (err) { toast(err.message, "error"); }
});

/* ------------------------------------------------------------------ email */

const MAIL_PACKAGES = { postfix: "postfix", msmtp: "msmtp-mta" };

function mailInstallButton() {
  const chosen = $("#mail-transport-select").value;
  const configured = state.mailData && state.mailData.transport;
  const button = $("#mail-install");
  button.textContent = `Install ${MAIL_PACKAGES[chosen]}`;
  // offer the install whenever the chosen transport is not the one known to be installed
  button.classList.toggle("hidden", !!(state.mailData && state.mailData.installed && chosen === configured));
}

async function loadMail() {
  const data = await api("/mail");
  state.mailData = data;
  const transport = data.transport || "postfix";
  $("#mail-transport-select").value = transport;
  const badge = $("#mail-status-badge");
  if (!data.installed) {
    badge.textContent = `${MAIL_PACKAGES[transport]} not installed`;
    badge.className = "badge warn";
  } else if (transport === "msmtp") {
    badge.textContent = "msmtp installed";
    badge.className = "badge ok";
  } else {
    badge.textContent = data.service_active ? "postfix active" : "postfix installed";
    badge.className = `badge ${data.service_active ? "ok" : "warn"}`;
  }
  mailInstallButton();
  $("#mail-host").value = data.host || "";
  $("#mail-port").value = data.port || 587;
  $("#mail-security").value = data.security || "starttls";
  $("#mail-username").value = data.username || "";
  $("#mail-from").value = data.from_address || "";
  $("#mail-report-to").value = data.report_to || "";
  $("#mail-report-mode").value = data.report_mode || "only-on-error";
  $("#mail-password-hint").textContent = data.credentials_set ? "(password on file)" : "";
  const msmtp = data.msmtp || {};
  const msmtpHint = $("#mail-msmtp-hint");
  if (msmtp.detected && !data.relayhost && transport === "postfix") {
    msmtpHint.classList.remove("hidden");
    msmtpHint.textContent =
      "Existing msmtp configuration found - the form is pre-filled from /etc/msmtprc. " +
      (msmtp.password_available
        ? "Leave the password blank and the msmtp password file is used automatically. "
        : "") +
      "Keep msmtp by choosing it under Delivery, or save with Postfix and use ‘Remove conflicting mailers’ so Postfix takes over sendmail.";
    $("#mail-host").value = msmtp.host || $("#mail-host").value;
    $("#mail-port").value = msmtp.port || $("#mail-port").value;
    $("#mail-security").value = msmtp.security || $("#mail-security").value;
    $("#mail-username").value = msmtp.username || $("#mail-username").value;
    if (!$("#mail-from").value) $("#mail-from").value = msmtp.from_address || "";
  } else {
    msmtpHint.classList.add("hidden");
  }
  const mailer = data.mailer || {};
  const conflicts = mailer.conflicts || [];
  const transportLine = $("#mail-transport");
  let transportText = mailer.sendmail
    ? `sendmail provided by ${mailer.sendmail_provider} (${mailer.sendmail})`
    : "no sendmail provider found";
  if (conflicts.length) transportText += ` · conflicts with: ${conflicts.join(", ")}`;
  if (mailer.msmtp_client && !conflicts.length) {
    transportText += " · msmtp client present (not used for delivery, left untouched)";
  }
  transportLine.textContent = transportText;
  $("#mail-remove-conflicts").classList.toggle("hidden", conflicts.length === 0);
  let summary = "No relay configured yet.";
  if (data.relayhost) {
    summary = transport === "msmtp"
      ? `msmtp hands mail to ${data.relayhost}, sending as ${data.from_address || "-"}.`
      : `Mail is relayed via ${data.relayhost}, sending as ${data.from_address || "-"} (sender domain ${data.myorigin || "-"}).`;
    if (data.envelope_sender) {
      summary += data.envelope_sender === data.from_address
        ? ` Envelope sender (MAIL FROM): ${data.envelope_sender}.`
        : ` The relay account owns the envelope sender, so messages leave with MAIL FROM ${data.envelope_sender} and From: ${data.from_address || "-"} - your mail server would reject the From: address as a sender it does not own.`;
    }
    if (transport === "postfix" && data.credentials_set && !data.sender_canonical_set) {
      summary += " Save these settings to pin the envelope sender to the relay account.";
    }
  }
  $("#mail-summary").textContent = summary;
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
    transport: $("#mail-transport-select").value,
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

$("#mail-transport-select").addEventListener("change", mailInstallButton);

$("#mail-install").addEventListener("click", async () => {
  const chosen = $("#mail-transport-select").value;
  try {
    const job = await api(`/mail/install?transport=${chosen}`, { method: "POST" });
    toast(`Installing ${MAIL_PACKAGES[chosen]}…`, "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

$("#mail-remove-conflicts").addEventListener("click", async () => {
  if (!window.confirm(
    `Remove the conflicting mail transfer agent(s)? ${(state.mailData && state.mailData.transport) === "msmtp" ? "msmtp" : "Postfix"} handles mail delivery afterwards. Their config files are kept.`,
  )) return;
  try {
    const job = await api("/mail/remove-conflicts", { method: "POST" });
    toast("Removing conflicting mailers…", "success");
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
      <td>${esc(u.full_name || "-")}</td>
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
  loadGroups();
}

$("#users-table").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-user]");
  if (button) openUser(button.dataset.user);
});

/* ----------------------------------------------------------------- groups */

function renderGroups(data) {
  state.groupsData = data;
  const showSystem = $("#groups-system").checked;
  const users = data.users || [];
  const rows = (data.groups || []).filter((g) => showSystem || !g.system).map((g) => {
    const members = (g.members || []).map((m) =>
      `<span class="chip"><code>${esc(m)}</code><button class="chip-x" title="Remove ${esc(m)}"
        data-group="${esc(g.name)}" data-remove-member="${esc(m)}">&times;</button></span>`).join(" ");
    const primary = (g.primary_of || []).length
      ? `<div class="muted">primary group of ${g.primary_of.map(esc).join(", ")}</div>` : "";
    const candidates = users.filter((u) => !(g.members || []).includes(u));
    return `<tr>
      <td><code>${esc(g.name)}</code>${g.system ? ' <span class="badge muted">system</span>' : ""}</td>
      <td>${esc(g.gid)}</td>
      <td>${members || '<span class="muted">no supplementary members</span>'}${primary}</td>
      <td class="nowrap">
        <select data-add-select="${esc(g.name)}">${candidates.map((u) => `<option value="${esc(u)}">${esc(u)}</option>`).join("")}</select>
        <button class="btn btn-small" data-add-member="${esc(g.name)}" ${candidates.length ? "" : "disabled"}>Add</button>
        ${g.deletable ? `<button class="btn btn-small btn-danger" data-delete-group="${esc(g.name)}">Delete</button>` : ""}
      </td>
    </tr>`;
  }).join("");
  $("#groups-table").innerHTML = `
    <thead><tr><th>Group</th><th>GID</th><th>Members</th><th></th></tr></thead>
    <tbody>${rows || "<tr><td colspan='4' class='muted'>No groups to show</td></tr>"}</tbody>`;
}

async function loadGroups() {
  try { renderGroups(await api("/groups")); } catch (err) { toast(err.message, "error"); }
}

$("#groups-system").addEventListener("change", () => { if (state.groupsData) renderGroups(state.groupsData); });

$("#groups-table").addEventListener("click", async (event) => {
  const target = event.target.closest("button");
  if (!target) return;
  try {
    if (target.dataset.removeMember) {
      const { group, removeMember } = target.dataset;
      if (!window.confirm(`Remove ${removeMember} from ${group}?`)) return;
      renderGroups(await api(`/groups/${encodeURIComponent(group)}/members/${encodeURIComponent(removeMember)}`, { method: "DELETE" }));
      toast(`${removeMember} removed from ${group}`, "success");
    } else if (target.dataset.addMember) {
      const group = target.dataset.addMember;
      const user = $(`select[data-add-select="${CSS.escape(group)}"]`).value;
      renderGroups(await api(`/groups/${encodeURIComponent(group)}/members`, { method: "POST", body: { user } }));
      toast(`${user} added to ${group}`, "success");
    } else if (target.dataset.deleteGroup) {
      const group = target.dataset.deleteGroup;
      if (!window.confirm(`Delete group ${group}?`)) return;
      renderGroups(await api(`/groups/${encodeURIComponent(group)}`, { method: "DELETE" }));
      toast(`Group ${group} deleted`, "success");
    }
  } catch (err) { toast(err.message, "error"); }
});

$("#group-create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = $("#new-group").value.trim();
  try {
    renderGroups(await api("/groups", { method: "POST", body: { name, system: $("#new-group-system").checked } }));
    $("#new-group").value = "";
    toast(`Group ${name} created`, "success");
  } catch (err) { toast(err.message, "error"); }
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
    // Always start from a clean key form: an edit left in flight for another
    // user would otherwise PUT a stale line index at the new account.
    resetKeyForm();
    renderKeys(data.keys || []);
    $("#user-modal").classList.remove("hidden");
    loadUserDepth(name);
  } catch (err) { toast(err.message, "error"); }
}

async function loadUserDepth(name) {
  try {
    const data = await api(`/users/${encodeURIComponent(name)}/aging`);
    const aging = data.aging || {};
    $("#aging-max-days").value = aging.max_days || "";
    $("#aging-warn-days").value = aging.warn_days || "";
    $("#aging-expiry").value = aging.account_expires || "never";
  } catch (err) { /* non-fatal */ }
  try {
    const data = await api(`/users/${encodeURIComponent(name)}/history?limit=15`);
    const rows = (data.entries || []).map((entry) => `
      <tr>
        <td class="muted">${esc(entry.login)}</td>
        <td><code>${esc(entry.terminal)}</code></td>
        <td class="muted">${esc(entry.source || "local")}</td>
        <td><span class="badge ${entry.status === "logged in" ? "ok" : "muted"}">${esc(entry.status)}</span></td>
        <td class="muted">${esc(entry.duration || "")}</td>
      </tr>`).join("");
    $("#user-history-table").innerHTML = `
      <thead><tr><th>When</th><th>Terminal</th><th>From</th><th>Status</th><th>Duration</th></tr></thead>
      <tbody>${rows || "<tr><td colspan='5' class='muted'>No logins recorded</td></tr>"}</tbody>`;
  } catch (err) { /* non-fatal */ }
  try {
    const data = await api("/sudoers");
    const hit = (data.dropins || []).find((d) => d.managed && d.user === name);
    $("#sudo-nopasswd").checked = !!(hit && hit.nopasswd);
    $("#sudo-status").textContent = hit
      ? `Sudo rule installed in ${hit.file} (${hit.nopasswd ? "NOPASSWD" : "password required"}).`
      : "No panel-managed sudo rule (this user may still sudo via the sudo group).";
  } catch (err) { /* non-fatal */ }
}

function renderKeys(keys) {
  state.editUserKeys = keys || [];
  // An edit in progress must not be thrown away by the refresh that follows a
  // save, but the index it points at only survives while the file is unchanged.
  if (state.editKeyIndex !== null) {
    const current = keys.find((k) => k.index === state.editKeyIndex);
    if (!current) state.editKeyIndex = null;
  }
  $("#user-keys-table").innerHTML = `
    <thead><tr><th>Type</th><th>Comment</th><th></th></tr></thead>
    <tbody>${keys.map((k) => `
      <tr>
        <td><code>${esc(k.type)}</code>${k.valid ? "" : ' <span class="badge warn">unrecognized</span>'}</td>
        <td>${esc(k.comment || "-")}</td>
        <td class="key-actions">
          <button class="btn btn-small" data-key-edit="${k.index}">Edit</button>
          <button class="btn btn-small btn-danger" data-key-index="${k.index}">Remove</button>
        </td>
      </tr>`).join("") || "<tr><td colspan='3' class='muted'>No keys installed</td></tr>"}</tbody>`;
}

function closeUserModal() {
  state.editUser = null;
  state.editUserKeys = [];
  resetKeyForm();
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

function resetKeyForm() {
  state.editKeyIndex = null;
  $("#user-key-label").textContent = "Add public key";
  $("#user-key-submit").textContent = "Add Key";
  $("#user-key-cancel").classList.add("hidden");
  $("#edit-key").value = "";
}

function startKeyEdit(index, raw) {
  state.editKeyIndex = index;
  $("#user-key-label").textContent = `Edit public key on line ${index + 1}`;
  $("#user-key-submit").textContent = "Update Key";
  $("#user-key-cancel").classList.remove("hidden");
  $("#edit-key").value = raw || "";
  $("#edit-key").focus();
}

$("#user-key-cancel").addEventListener("click", resetKeyForm);

$("#user-key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.editUser) return;
  const key = $("#edit-key").value.trim();
  if (!key) { toast("Paste a public key first", "error"); return; }
  const editing = state.editKeyIndex;
  try {
    const data = editing === null
      ? await api(`/users/${encodeURIComponent(state.editUser)}/keys`, {
          method: "POST",
          body: { key },
        })
      : await api(`/users/${encodeURIComponent(state.editUser)}/keys/${editing}`, {
          method: "PUT",
          body: { key },
        });
    resetKeyForm();
    renderKeys(data.keys || []);
    toast(editing === null ? "SSH key added" : "SSH key updated", "success");
  } catch (err) { toast(err.message, "error"); }
});

$("#user-keys-table").addEventListener("click", async (event) => {
  if (!state.editUser) return;
  const edit = event.target.closest("button[data-key-edit]");
  if (edit) {
    const index = Number(edit.dataset.keyEdit);
    const key = (state.editUserKeys || []).find((k) => k.index === index);
    startKeyEdit(index, key ? key.raw : "");
    return;
  }
  const button = event.target.closest("button[data-key-index]");
  if (!button) return;
  const index = Number(button.dataset.keyIndex);
  try {
    const data = await api(
      `/users/${encodeURIComponent(state.editUser)}/keys/${index}`,
      { method: "DELETE" },
    );
    resetKeyForm();
    renderKeys(data.keys || []);
    toast("SSH key removed", "info");
  } catch (err) { toast(err.message, "error"); }
});

$("#user-aging-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.editUser) return;
  const maxDays = $("#aging-max-days").value.trim();
  const warnDays = $("#aging-warn-days").value.trim();
  try {
    await api(`/users/${encodeURIComponent(state.editUser)}/aging`, {
      method: "POST",
      body: {
        max_days: maxDays === "" ? null : parseInt(maxDays, 10),
        warn_days: warnDays === "" ? null : parseInt(warnDays, 10),
        expiry: $("#aging-expiry").value.trim() || null,
      },
    });
    toast("Password aging updated", "success");
  } catch (err) { toast(err.message, "error"); }
});

$("#sudo-save").addEventListener("click", async () => {
  if (!state.editUser) return;
  try {
    await api(`/sudoers/${encodeURIComponent(state.editUser)}`, {
      method: "POST",
      body: { nopasswd: $("#sudo-nopasswd").checked },
    });
    toast("Sudo rule installed", "success");
    loadUserDepth(state.editUser);
  } catch (err) { toast(err.message, "error"); }
});

$("#sudo-remove").addEventListener("click", async () => {
  if (!state.editUser) return;
  try {
    await api(`/sudoers/${encodeURIComponent(state.editUser)}`, { method: "DELETE" });
    toast("Sudo rule removed", "info");
    loadUserDepth(state.editUser);
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
  $$("#view-software .tab-panel").forEach((panel) => panel.classList.add("hidden"));
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
    .join("") || "<li class='muted'>Nothing to remove - nice and tidy.</li>";
  $("#pkg-updates-table").innerHTML = `
    <thead><tr><th>Package</th><th>Version</th><th></th><th></th></tr></thead>
    <tbody>${(upgradable.packages || []).map((p) => pkgRow(p, "Install", "btn-primary")).join("")
      || "<tr><td colspan='4' class='muted'>System is up to date</td></tr>"}</tbody>`;
  renderInstalled();
  if (!state.updateChecked) checkUpdate();
}

/* ------------------------------------------------------ linustart updates */

async function checkUpdate() {
  const info = $("#update-info");
  info.textContent = "Checking GitHub…";
  try {
    const data = await api("/update/check");
    state.updateChecked = true;
    state.updateTag = data.tag || "";
    // A checkout reports the tag it descends from plus its own commits, so
    // never claim it is up to date on the strength of the declared version.
    const fromGit = data.version_source === "git";
    const commitNote = fromGit && data.ahead
      ? `<br><span class="muted">Commit <code>${esc(data.commit || "")}</code>, ${data.ahead} commit${data.ahead === 1 ? "" : "s"} past <code>${esc(data.current_base || "")}</code>.</span>`
      : "";
    if (data.no_releases) {
      info.innerHTML =
        `Installed: <code>${esc(data.current)}</code> <span class="badge muted">no releases yet</span>` +
        commitNote +
        `<br><span class="muted">${esc(data.detail || "")} - publish a GitHub release (e.g. v0.2.0) to enable in-panel updates.</span>`;
      $("#update-install").disabled = true;
      return;
    }
    info.innerHTML =
      `Installed: <code>${esc(data.current)}</code> · Latest: <code>${esc(data.latest)}</code> ` +
      (data.newer_available
        ? '<span class="badge warn">update available</span>'
        : '<span class="badge ok">up to date</span>') +
      (data.checksum_published
        ? ' <span class="badge ok">SHA-256 verified on install</span>'
        : ` <span class="badge warn">no checksum published${data.require_checksum ? " - install refused" : ""}</span>`) +
      commitNote +
      (data.update_supported
        ? ""
        : '<br><span class="muted">Source checkout - updates apply to install.sh installs; use git pull here.</span>');
    $("#update-install").disabled = !data.newer_available || !data.update_supported;
    $("#update-notes").textContent = data.notes || "This release has no notes.";
    const link = $("#update-link");
    if (data.release_url) {
      link.href = data.release_url;
      link.classList.remove("hidden");
    }
  } catch (err) {
    info.textContent = err.message;
    $("#update-install").disabled = true;
  }
}

$("#update-check").addEventListener("click", checkUpdate);

$("#update-install").addEventListener("click", async () => {
  if (!window.confirm("Install the update and restart the panel? The panel is unreachable for a few seconds during the restart.")) return;
  try {
    const job = await api("/update/install", { method: "POST", body: { tag: state.updateTag } });
    toast("Update started", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

$("#update-rollback").addEventListener("click", async () => {
  if (!window.confirm("Roll back to the most recent application backup and restart the panel?")) return;
  try {
    const job = await api("/update/rollback", { method: "POST" });
    toast("Rollback started", "success");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

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
      if (state.view === "network") loadNetwork();
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

/* --------------------------------------------------------------- firewall */

async function loadFirewall() {
  const data = await api("/firewall");
  const firewalld = data.backend === "firewalld";
  $("#fw-backend").textContent = `backend: ${data.backend}${firewalld && data.zone ? ` (zone ${data.zone})` : ""}`;
  // firewalld zones only filter incoming traffic
  $("#fw-outgoing").disabled = firewalld;
  $('#fw-direction option[value="out"]').disabled = firewalld;
  const status = $("#fw-status");
  status.textContent = data.enabled ? "enabled" : "disabled";
  status.className = `badge ${data.enabled ? "ok" : "warn"}`;
  $("#fw-incoming").value = data.default_incoming || "deny";
  $("#fw-outgoing").value = data.default_outgoing || "allow";
  $("#fw-enabled").checked = !!data.enabled;
  const rows = (data.rules || []).map((rule, index) => {
    let target = rule.to
      ? `<code>${esc(rule.to)}</code>`
      : `<code>${esc((rule.protocol === "any" ? "all" : rule.protocol) + (rule.port ? `/${rule.port}` : ""))}</code>`;
    if (rule.action === "custom") target = `<code>${esc(rule.raw || "")}</code>`;
    else if (rule.label) target += ` <span class="muted">${esc(rule.label)}</span>`;
    const side = rule.direction === "out" ? "to" : "from";
    const address = rule.to ? rule.from : rule.address;
    return `<tr>
      <td><span class="badge">${rule.direction === "out" ? "out" : "in"}</span></td>
      <td><span class="badge ${rule.action === "allow" ? "ok" : rule.action === "custom" ? "muted" : "danger"}">${esc(rule.action)}</span></td>
      <td>${target}</td>
      <td class="muted">${side} ${esc(address || "any")}${rule.ipv6 ? " (v6)" : ""}</td>
      <td><button class="btn btn-small btn-danger" data-fw-remove="${index}">Remove</button></td>
    </tr>`;
  }).join("");
  $("#fw-rules-table").innerHTML = `
    <thead><tr><th>Dir</th><th>Action</th><th>Target</th><th>Peer</th><th></th></tr></thead>
    <tbody>${rows || "<tr><td colspan='5' class='muted'>No rules configured</td></tr>"}</tbody>`;
}

$("#fw-rules-table").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-fw-remove]");
  if (!button) return;
  if (!window.confirm("Remove this firewall rule?")) return;
  try {
    const result = await api(`/firewall/rules/${button.dataset.fwRemove}`, { method: "DELETE" });
    toast("Rule removed - confirm within 90s to keep it", "success");
    startRevertBar(result.session);
    loadFirewall();
  } catch (err) { toast(err.message, "error"); }
});

$("#fw-rule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await api("/firewall/rules", {
      method: "POST",
      body: {
        action: $("#fw-action").value,
        direction: $("#fw-direction").value,
        protocol: $("#fw-protocol").value,
        port: $("#fw-port").value.trim(),
        address: $("#fw-address").value.trim() || "any",
      },
    });
    toast("Rule added - confirm within 90s to keep it", "success");
    startRevertBar(result.session);
    $("#fw-rule-form").reset();
    loadFirewall();
  } catch (err) { toast(err.message, "error"); }
});

$("#fw-policy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await api("/firewall", {
      method: "POST",
      body: {
        enabled: $("#fw-enabled").checked,
        default_incoming: $("#fw-incoming").value,
        default_outgoing: $("#fw-outgoing").value,
      },
    });
    toast(
      result.ssh_rule_added
        ? "Policies applied - an SSH allow rule was added automatically"
        : "Policies applied - confirm within 90s to keep them",
      "success",
    );
    startRevertBar(result.session);
    loadFirewall();
  } catch (err) { toast(err.message, "error"); }
});

/* --------------------------------------------------------------------- ssh */

async function loadSsh() {
  const data = await api("/ssh");
  const typed = data.typed || {};
  $("#ssh-port").value = typed.Port;
  $("#ssh-root-login").value = typed.PermitRootLogin;
  $("#ssh-password-auth").checked = !!typed.PasswordAuthentication;
  $("#ssh-pubkey-auth").checked = !!typed.PubkeyAuthentication;
  $("#ssh-x11").checked = !!typed.X11Forwarding;
  $("#ssh-max-auth").value = typed.MaxAuthTries;
  $("#ssh-alive-interval").value = typed.ClientAliveInterval;
  $("#ssh-alive-count").value = typed.ClientAliveCountMax;
  const badge = $("#ssh-badge");
  badge.textContent = data.service_active === false ? "sshd not active" : "sshd active";
  badge.className = `badge ${data.service_active === false ? "warn" : "ok"}`;
  const validation = $("#ssh-validation");
  validation.textContent = data.validation_error ? "config problem" : "config valid";
  validation.className = `badge ${data.validation_error ? "danger" : "ok"}`;
  validation.title = data.validation_error || "";
}

async function submitSsh(body, message) {
  try {
    const result = await api("/ssh", { method: "POST", body });
    toast(message, "success");
    startRevertBar(result.session);
    loadSsh();
  } catch (err) { toast(err.message, "error"); }
}

$("#ssh-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitSsh(
    {
      port: parseInt($("#ssh-port").value.trim(), 10),
      permit_root_login: $("#ssh-root-login").value,
      password_authentication: $("#ssh-password-auth").checked,
      pubkey_authentication: $("#ssh-pubkey-auth").checked,
    },
    "SSH access settings applied - confirm within 90s",
  );
});

$("#ssh-extra-form").addEventListener("submit", (event) => {
  event.preventDefault();
  submitSsh(
    {
      x11_forwarding: $("#ssh-x11").checked,
      max_auth_tries: parseInt($("#ssh-max-auth").value.trim(), 10),
      client_alive_interval: parseInt($("#ssh-alive-interval").value.trim(), 10),
      client_alive_count_max: parseInt($("#ssh-alive-count").value.trim(), 10),
    },
    "SSH hardening applied - confirm within 90s",
  );
});

/* --------------------------------------------------------------- services */

async function loadServices() {
  const query = ($("#svc-filter").value || "").trim();
  const data = await api(`/services?q=${encodeURIComponent(query)}`);
  $("#svc-count").textContent = `${data.count} service(s)`;
  const rows = (data.units || []).map((unit) => `
    <tr>
      <td><code>${esc(unit.unit)}</code></td>
      <td><span class="badge ${unit.active === "active" ? "ok" : unit.active === "failed" ? "danger" : "muted"}">${esc(unit.active)}</span></td>
      <td class="muted">${esc(unit.sub)}</td>
      <td><span class="badge ${unit.enabled === "enabled" ? "ok" : "muted"}">${esc(unit.enabled)}</span></td>
      <td class="muted">${esc(unit.description)}</td>
      <td><button class="btn btn-small" data-svc-unit="${esc(unit.unit)}">Details</button></td>
    </tr>`).join("");
  $("#svc-table").innerHTML = `
    <thead><tr><th>Unit</th><th>Active</th><th>Sub</th><th>On boot</th><th>Description</th><th></th></tr></thead>
    <tbody>${rows || "<tr><td colspan='6' class='muted'>No services match</td></tr>"}</tbody>`;
}

$("#svc-filter").addEventListener("input", loadServices);
$("#svc-refresh").addEventListener("click", loadServices);

$("#svc-table").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-svc-unit]");
  if (button) openService(button.dataset.svcUnit);
});

function renderOverride(data) {
  $("#svc-override-path").textContent = data.path || "";
  $("#svc-override").value = data.content || "";
  $("#svc-definition").textContent = data.definition || "";
}

async function loadOverride(unit) {
  try { renderOverride(await api(`/services/${encodeURIComponent(unit)}/override`)); }
  catch (err) { $("#svc-definition").textContent = err.message; }
}

$("#svc-override-save").addEventListener("click", async () => {
  if (!state.svcEdit) return;
  const content = $("#svc-override").value;
  if (!content.trim() && !window.confirm(`Remove the override for ${state.svcEdit}?`)) return;
  try {
    renderOverride(await api(`/services/${encodeURIComponent(state.svcEdit)}/override`, {
      method: "PUT", body: { content },
    }));
    toast(content.trim() ? "Override saved - restart the service to apply it" : "Override removed", "success");
  } catch (err) { toast(err.message, "error"); }
});

async function openService(unit) {
  try {
    const data = await api(`/services/${encodeURIComponent(unit)}`);
    state.svcEdit = unit;
    $("#service-modal-title").textContent = data.unit;
    $("#service-modal-meta").textContent =
      `${data.description} · ${data.active}/${data.sub} · ${data.enabled || "unknown"} · pid ${data.main_pid || "-"}`;
    $("#service-modal-log").textContent = (data.journal || []).join("\n") || "No journal entries.";
    loadOverride(unit);
    $("#service-modal").classList.remove("hidden");
  } catch (err) { toast(err.message, "error"); }
}

$("#service-modal-close").addEventListener("click", () => $("#service-modal").classList.add("hidden"));

$("#service-modal").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-svc-action]");
  if (!button || !state.svcEdit) return;
  const action = button.dataset.svcAction;
  if ((action === "stop" || action === "disable") && !window.confirm(`${action} ${state.svcEdit}?`)) return;
  try {
    const job = await api(`/services/${encodeURIComponent(state.svcEdit)}/action/${action}`, { method: "POST" });
    toast(`${action} requested for ${state.svcEdit}`, "success");
    $("#service-modal").classList.add("hidden");
    openJob(job.id);
  } catch (err) { toast(err.message, "error"); }
});

/* ----------------------------------------------------------------- storage */

async function loadStorage() {
  const data = await api("/disk");
  const rows = (data.filesystems || []).map((fs) => `
    <tr>
      <td><code>${esc(fs.source)}</code></td>
      <td><code>${esc(fs.target)}</code></td>
      <td class="muted">${esc(fs.fstype)}</td>
      <td>${fs.percent}% · ${fmtBytes(fs.used)} / ${fmtBytes(fs.size)}</td>
      <td class="muted">${fmtBytes(fs.avail)} free</td>
    </tr>`).join("");
  $("#disk-table").innerHTML = `
    <thead><tr><th>Device</th><th>Mount</th><th>Type</th><th>Usage</th><th></th></tr></thead>
    <tbody>${rows || "<tr><td colspan='5' class='muted'>No filesystems found</td></tr>"}</tbody>`;
}

$("#du-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const path = $("#du-path").value.trim();
  if (!path) return;
  try {
    const job = await api("/disk/scan", { method: "POST", body: { path } });
    state.duJob = job.id;
    $("#du-status").textContent = `Scanning ${path}…`;
    clearInterval(state.duTimer);
    pollDu();
    state.duTimer = setInterval(pollDu, 1500);
  } catch (err) { toast(err.message, "error"); }
});

async function pollDu() {
  if (!state.duJob) return;
  try {
    const data = await api(`/disk/usage/${state.duJob}`);
    renderDu(data.entries);
    if (data.job.status !== "running") {
      clearInterval(state.duTimer);
      $("#du-status").textContent = `Scan ${data.job.status} · ${data.entries.length} subdirectory(ies) listed.`;
      state.duJob = null;
    }
  } catch (err) {
    clearInterval(state.duTimer);
    toast(err.message, "error");
  }
}

function renderDu(entries) {
  const rows = (entries || []).slice(0, 100).map((entry) => `
    <tr>
      <td><code>${esc(entry.path)}</code></td>
      <td>${fmtBytes(entry.size)}</td>
    </tr>`).join("");
  $("#du-table").innerHTML = `
    <thead><tr><th>Directory</th><th>Size</th></tr></thead>
    <tbody>${rows || "<tr><td colspan='2' class='muted'>Nothing scanned yet</td></tr>"}</tbody>`;
}

/* ------------------------------------------------------- logs & processes */

$("#logs-tabs").addEventListener("click", (event) => {
  const tab = event.target.closest(".tab");
  if (!tab) return;
  $$("#logs-tabs .tab").forEach((t) => t.classList.toggle("active", t === tab));
  $$("#view-logs .tab-panel").forEach((panel) => panel.classList.add("hidden"));
  $(`#tab-${tab.dataset.tab}`).classList.remove("hidden");
  if (tab.dataset.tab === "processes") loadProcesses();
});

async function loadLogsView() {
  try {
    const data = await api("/logs/files");
    state.logFiles = data.files || [];
  } catch (err) { state.logFiles = []; }
  const current = $("#log-source").value;
  $("#log-source").innerHTML =
    '<option value="journal">journalctl (systemd)</option>' +
    state.logFiles.map((f) => `<option value="file:${esc(f.name)}">/var/log/${esc(f.name)}</option>`).join("");
  if (current) $("#log-source").value = current;
  await loadJournal();
}

const LOG_KEEP_LINES = 5000;

function logParams() {
  const source = $("#log-source").value || "journal";
  const lines = $("#log-lines").value;
  if (source === "journal") {
    const unit = encodeURIComponent($("#log-unit").value.trim());
    const priority = encodeURIComponent($("#log-priority").value);
    return { source, path: `/logs/journal?lines=${lines}&unit=${unit}&priority=${priority}` };
  }
  const name = source.slice("file:".length);
  return { source, path: `/logs/files/${encodeURIComponent(name)}?lines=${lines}` };
}

async function loadJournal() {
  stopLogFollow();
  try {
    const { path } = logParams();
    const data = await api(path);
    state.logCursor = data.cursor || "";
    state.logOffset = data.offset;
    $("#log-output").textContent = (data.lines || []).join("\n") || "No entries.";
    const out = $("#log-output");
    out.scrollTop = out.scrollHeight;
    if ($("#log-follow").checked) startLogFollow();
  } catch (err) { toast(err.message, "error"); }
}

// Following asks only for what is new: entries after the journal cursor, or
// bytes after the last offset of a file.
function startLogFollow() {
  stopLogFollow();
  state.logTimer = setInterval(followTick, 3000);
}

function stopLogFollow() {
  clearInterval(state.logTimer);
  state.logTimer = null;
}

async function followTick() {
  const { source, path } = logParams();
  const extra = source === "journal"
    ? (state.logCursor ? `&after_cursor=${encodeURIComponent(state.logCursor)}` : "")
    : (state.logOffset !== undefined && state.logOffset !== null ? `&offset=${state.logOffset}` : "");
  try {
    const data = await api(path + extra);
    if (source === "journal") state.logCursor = data.cursor || state.logCursor;
    else state.logOffset = data.offset;
    const fresh = data.lines || [];
    if (!fresh.length) return;
    const out = $("#log-output");
    const atBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 40;
    const existing = out.textContent === "No entries." ? [] : out.textContent.split("\n");
    out.textContent = mergeLogLines(existing, fresh, LOG_KEEP_LINES).join("\n");
    if (atBottom) out.scrollTop = out.scrollHeight;
  } catch (err) {
    stopLogFollow();
    $("#log-follow").checked = false;
    toast(err.message, "error");
  }
}

$("#log-follow").addEventListener("change", (event) => {
  if (event.target.checked) startLogFollow(); else stopLogFollow();
});

$("#log-form").addEventListener("submit", (event) => {
  event.preventDefault();
  loadJournal();
});

async function loadProcesses() {
  try {
    const data = await api(`/processes?sort=${$("#proc-sort").value}`);
    $("#proc-count").textContent = `${data.count} processes`;
    const rows = (data.processes || []).slice(0, 200).map((p) => `
      <tr>
        <td><code>${p.pid}</code></td>
        <td>${esc(p.user)}</td>
        <td>${p.cpu.toFixed(1)}%</td>
        <td>${p.mem.toFixed(1)}%</td>
        <td class="muted">${fmtBytes(p.rss_kb * 1024)}</td>
        <td class="muted">${esc(p.args)}</td>
        <td>
          <button class="btn btn-small" data-kill="${p.pid}" data-signal="TERM">TERM</button>
          <button class="btn btn-small btn-danger" data-kill="${p.pid}" data-signal="KILL">KILL</button>
        </td>
      </tr>`).join("");
    $("#proc-table").innerHTML = `
      <thead><tr><th>PID</th><th>User</th><th>CPU</th><th>MEM</th><th>RSS</th><th>Command</th><th></th></tr></thead>
      <tbody>${rows || "<tr><td colspan='7' class='muted'>No processes found</td></tr>"}</tbody>`;
  } catch (err) { toast(err.message, "error"); }
}

$("#proc-refresh").addEventListener("click", loadProcesses);
$("#proc-sort").addEventListener("change", loadProcesses);

$("#proc-table").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-kill]");
  if (!button) return;
  const pid = button.dataset.kill;
  if (!window.confirm(`Send SIG${button.dataset.signal} to PID ${pid}?`)) return;
  try {
    await api("/processes/kill", {
      method: "POST",
      body: { pid: parseInt(pid, 10), signal: button.dataset.signal },
    });
    toast(`SIG${button.dataset.signal} sent to PID ${pid}`, "success");
    loadProcesses();
  } catch (err) { toast(err.message, "error"); }
});

/* ---------------------------------------------------------------- terminal */

// xterm.js (vendored under /static/vendor) renders the shell: full-screen
// programs, colours, selection and paste all work, and the fit add-on keeps
// the PTY's size in step with the browser window.
const term = { ws: null, xterm: null, fit: null, resizeTimer: null };

function termSend(message) {
  if (term.ws && term.ws.readyState === WebSocket.OPEN) term.ws.send(JSON.stringify(message));
}

function termEnsure() {
  if (term.xterm) return term.xterm;
  if (typeof Terminal === "undefined" || typeof FitAddon === "undefined") {
    toast("The terminal library failed to load", "error");
    return null;
  }
  const xterm = new Terminal({
    cursorBlink: true,
    fontFamily: 'ui-monospace, "SF Mono", Menlo, Consolas, monospace',
    fontSize: 13,
    scrollback: 5000,
    theme: { background: "#0b1220", foreground: "#d7e0ea" },
  });
  const fit = new FitAddon.FitAddon();
  xterm.loadAddon(fit);
  xterm.open($("#term-screen"));
  // onData carries typing and pasted text alike.
  xterm.onData((data) => termSend({ type: "input", data }));
  xterm.onResize(({ cols, rows }) => termSend({ type: "resize", cols, rows }));
  window.addEventListener("resize", () => {
    clearTimeout(term.resizeTimer);
    term.resizeTimer = setTimeout(termFit, 150);
  });
  term.xterm = xterm;
  term.fit = fit;
  return xterm;
}

function termFit() {
  if (!term.fit || $("#view-terminal").classList.contains("hidden")) return;
  try { term.fit.fit(); } catch (err) { /* not laid out yet */ }
}

function termConnect() {
  if (term.ws) return;
  const xterm = termEnsure();
  if (!xterm) return;
  termFit();
  xterm.reset();
  const user = $("#term-user").value;
  const protocol = location.protocol === "https:" ? "wss" : "ws";
  // The token goes in the first message, not the URL: query strings land in
  // server access logs.
  const params = new URLSearchParams({
    user,
    cols: String(xterm.cols),
    rows: String(xterm.rows),
  });
  const ws = new WebSocket(`${protocol}://${location.host}/api/terminal/ws?${params}`);
  term.ws = ws;
  $("#term-status").textContent = "Connecting…";
  ws.onopen = () => {
    ws.send(JSON.stringify({ type: "auth", token: state.token }));
    $("#term-status").textContent = `Connected as ${user || "root"} (session recorded)`;
    xterm.focus();
  };
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.type === "output") xterm.write(message.data);
    else if (message.type === "closed") {
      $("#term-status").textContent = message.detail === "idle timeout"
        ? "Session closed after being idle" : "Session closed";
      term.ws = null;
    } else if (message.type === "error") { toast(message.detail, "error"); termDisconnect(); }
  };
  ws.onclose = (event) => {
    term.ws = null;
    if (event.code === 4401) toast("Terminal authentication failed - check the access token", "error");
    if (event.code === 4429) toast("Too many wrong tokens from this address - try again later", "error");
    if (!$("#term-status").textContent.startsWith("Session closed")) $("#term-status").textContent = "Disconnected";
  };
}

function termDisconnect() {
  if (term.ws) {
    try { term.ws.send(JSON.stringify({ type: "close" })); } catch (err) { /* already gone */ }
    term.ws.close();
    term.ws = null;
  }
  $("#term-status").textContent = "Disconnected";
}

$("#term-connect").addEventListener("click", termConnect);
$("#term-disconnect").addEventListener("click", termDisconnect);

async function loadTerminal() {
  try {
    const data = await api("/users");
    const current = $("#term-user").value;
    $("#term-user").innerHTML = (data.users || [])
      .map((u) => `<option value="${esc(u.name)}">${esc(u.name)}</option>`).join("");
    if (current) $("#term-user").value = current;
  } catch (err) { toast(err.message, "error"); }
  $("#term-status").textContent = term.ws ? "Connected" : "Not connected";
  // The view was hidden until now, so this is the first moment it has a size.
  termEnsure();
  termFit();
}

/* ------------------------------------------------------------------- init */

// Do not open the token modal just because nothing is stored yet: an install
// with no token configured never returns 401, so it would sit in front of the
// panel forever. api() opens it on a real 401, and the logout button opens it
// when a token is needed again.
loadView();
resumePendingSession();

// A change applied before this page was loaded (or before the panel
// restarted) is still waiting for confirmation: show its countdown.
async function resumePendingSession() {
  try {
    const data = await api("/sessions");
    if (!state.session && (data.sessions || []).length) startRevertBar(data.sessions[0]);
  } catch (err) { /* not signed in yet; the view loader reports that */ }
}
