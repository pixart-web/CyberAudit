"use strict";
// Minimal braces@3-compatible surface used by micromatch: braces(pattern, opts) -> string[].
// Expansion is delegated to brace-expansion (patched, bounded), so the vulnerable
// stack-exhaustion parser in braces@<=3.0.3 is not used.
const mod = require("brace-expansion");
const expandFn = typeof mod === "function" ? mod : mod.expand;
const MAX = 10000;
function braces(input, options) {
  const list = Array.isArray(input) ? input : [String(input)];
  const out = [];
  for (const p of list) {
    if (typeof p !== "string" || p.length > 65536) throw new TypeError("Invalid brace pattern");
    for (const r of expandFn(p, { max: MAX })) out.push(r);
  }
  return Array.from(new Set(out));
}
braces.expand = (input, options) => braces(input, { ...options, expand: true });
braces.create = braces;
braces.parse = (input) => [input];
braces.compile = (input) => braces(input);
module.exports = braces;
