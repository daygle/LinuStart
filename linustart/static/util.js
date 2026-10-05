/* Pure helpers shared by app.js. Kept free of the DOM so tests/js can load
   them under Node (node --test); in the browser they are plain globals. */
"use strict";

function esc(value) {
  const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value === undefined || value === null ? "" : value).replace(/[&<>"']/g, (c) => map[c]);
}

function fmtBytes(bytes) {
  if (!bytes) return "-";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function fmtUptime(seconds) {
  if (!seconds) return "-";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${d}d ${h}h ${m}m`;
}

// The smallest "nice" axis maximum (1, 2, 2.5, 5 × 10^n) at or above value.
function niceMax(value) {
  if (!(value > 0)) return 1;
  const step = Math.pow(10, Math.floor(Math.log10(value)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * step >= value) return m * step;
  return 10 * step;
}

function fmtMetric(value, unit) {
  if (value === null || value === undefined) return "-";
  return unit === "%" ? `${Number(value).toFixed(1)}%` : Number(value).toFixed(2);
}

// Append followed log lines, keeping only the newest `keep`.
function mergeLogLines(existing, fresh, keep) {
  return existing.concat(fresh).slice(-keep);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { esc, fmtBytes, fmtUptime, niceMax, fmtMetric, mergeLogLines };
}
