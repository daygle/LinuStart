// ESLint flat config for the panel's browser scripts. Core rules only, so CI
// needs nothing but `npx eslint@9` - no plugin or preset packages.
"use strict";

const browser = [
  "window", "document", "localStorage", "location", "fetch", "WebSocket", "URLSearchParams",
  "setTimeout", "clearTimeout", "setInterval", "clearInterval", "getComputedStyle", "CSS",
  "console", "Event",
];
const fromScripts = ["Terminal", "FitAddon"]; // vendor/xterm.js, vendor/addon-fit.js
const fromUtil = ["esc", "fmtBytes", "fmtUptime", "niceMax", "fmtMetric", "mergeLogLines"]; // util.js
const readonly = (names) => Object.fromEntries(names.map((name) => [name, "readonly"]));

const rules = {
  "no-undef": "error",
  "no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
  "no-redeclare": "error",
  "no-dupe-keys": "error",
  "no-duplicate-case": "error",
  "no-unreachable": "error",
  "no-const-assign": "error",
  "no-func-assign": "error",
  "no-self-assign": "error",
  "no-self-compare": "error",
  "no-cond-assign": "error",
  "no-constant-condition": ["error", { checkLoops: false }],
  "no-empty": ["error", { allowEmptyCatch: true }],
  "no-fallthrough": "error",
  "no-sparse-arrays": "error",
  "no-unsafe-finally": "error",
  "no-unsafe-negation": "error",
  "use-isnan": "error",
  "valid-typeof": "error",
  "eqeqeq": ["error", "smart"],
  "no-var": "error",
  "prefer-const": "error",
};

module.exports = [
  { ignores: ["linustart/static/vendor/**"] },
  {
    files: ["linustart/static/app.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: { ...readonly(browser), ...readonly(fromScripts), ...readonly(fromUtil) },
    },
    rules,
  },
  {
    files: ["linustart/static/util.js"],
    languageOptions: { ecmaVersion: 2022, sourceType: "script", globals: { module: "readonly" } },
    // the helpers are used from app.js, which ESLint cannot see across files
    rules: { ...rules, "no-unused-vars": "off" },
  },
  {
    files: ["tests/js/**/*.js", "eslint.config.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "commonjs",
      globals: { require: "readonly", module: "writable", __dirname: "readonly", console: "readonly" },
    },
    rules,
  },
];
