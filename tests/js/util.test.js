// Unit tests for the browser helpers: node --test tests/js/
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const util = require("../../linustart/static/util.js");

test("esc neutralises every HTML-significant character", () => {
  assert.equal(util.esc(`<img src=x onerror="a('b')">&`), "&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;");
  assert.equal(util.esc(null), "");
  assert.equal(util.esc(undefined), "");
  assert.equal(util.esc(0), "0");
});

test("fmtBytes picks binary units", () => {
  assert.equal(util.fmtBytes(0), "-");
  assert.equal(util.fmtBytes(512), "512 B");
  assert.equal(util.fmtBytes(1536), "1.5 KiB");
  assert.equal(util.fmtBytes(10 * 1024 * 1024), "10 MiB");
  assert.equal(util.fmtBytes(5 * 1024 ** 5), "5120 TiB");
});

test("fmtUptime", () => {
  assert.equal(util.fmtUptime(0), "-");
  assert.equal(util.fmtUptime(90061), "1d 1h 1m");
});

test("niceMax rounds up to 1/2/2.5/5 steps", () => {
  assert.equal(util.niceMax(0), 1);
  assert.equal(util.niceMax(-3), 1);
  assert.equal(util.niceMax(0.7), 1);
  assert.equal(util.niceMax(1.3), 2);
  assert.equal(util.niceMax(2.2), 2.5);
  assert.equal(util.niceMax(4.4), 5);
  assert.equal(util.niceMax(8.1), 10);
  assert.equal(util.niceMax(120), 200);
});

test("fmtMetric", () => {
  assert.equal(util.fmtMetric(42, "%"), "42.0%");
  assert.equal(util.fmtMetric(0.456, ""), "0.46");
  assert.equal(util.fmtMetric(null, "%"), "-");
});

test("mergeLogLines keeps the newest lines", () => {
  assert.deepEqual(util.mergeLogLines(["a", "b"], ["c"], 5), ["a", "b", "c"]);
  assert.deepEqual(util.mergeLogLines(["a", "b", "c"], ["d", "e"], 3), ["c", "d", "e"]);
});
