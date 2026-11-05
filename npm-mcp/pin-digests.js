#!/usr/bin/env node
'use strict';

/*
 * pin-digests.js - write, or check, the per-asset sha256 digests this package pins.
 *
 *   node pin-digests.js --write <checksums.txt>   pin every asset the wrapper can fetch
 *   node pin-digests.js --check                   refuse a package that does not pin them all
 *
 * The digests come from the checksums.txt of the release named by `whisperCliVersion`. Once
 * they sit in package.json they ride in the immutable npm tarball, so a version of this
 * package resolves to the same bytes even if an asset is later replaced under the tag.
 * `--check` runs before every pack (the prepack script), so a package that pins nothing, or
 * pins a set that misses a platform, can never be published.
 */

const fs = require('fs');
const path = require('path');
const { TARGETS, HEX64 } = require('./bin/whisper-mcp.js');

const PKG_PATH = path.join(__dirname, 'package.json');

function fail(msg) {
  process.stderr.write(`pin-digests: ${msg}\n`);
  process.exit(1);
}

/** Parse "<hex>  <name>" lines into { name: hex }, refusing anything that is not one. */
function parseChecksums(txt) {
  const out = {};
  for (const raw of String(txt).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const m = /^([0-9a-fA-F]{64})\s+\*?(\S+)$/.exec(line);
    if (!m) fail(`not a checksum line: ${JSON.stringify(line)}`);
    out[m[2]] = m[1].toLowerCase();
  }
  return out;
}

/** The problems with a pin set, one line each; empty when every asset is pinned exactly once. */
function problems(pins) {
  if (!pins || typeof pins !== 'object' || Array.isArray(pins)) {
    return ['package.json has no whisperCliDigests object'];
  }
  const want = Object.values(TARGETS);
  const out = [];
  for (const a of want) {
    if (!(a in pins)) out.push(`no digest pinned for ${a}`);
    else if (typeof pins[a] !== 'string' || !HEX64.test(pins[a])) out.push(`the digest pinned for ${a} is not a lowercase sha256`);
  }
  for (const k of Object.keys(pins)) {
    if (!want.includes(k)) out.push(`${k} is pinned but the wrapper never fetches it`);
  }
  return out;
}

function main(argv) {
  const pkg = JSON.parse(fs.readFileSync(PKG_PATH, 'utf8'));
  if (argv[0] === '--check' && argv.length === 1) {
    const p = problems(pkg.whisperCliDigests);
    if (p.length) fail(`REFUSING: ${p.join('; ')}. Run: node pin-digests.js --write <checksums.txt of v${pkg.whisperCliVersion}>`);
    process.stderr.write(`pin-digests: ${Object.keys(pkg.whisperCliDigests).length} digests pinned for v${pkg.whisperCliVersion}\n`);
    return;
  }
  if (argv[0] === '--write' && argv.length === 2) {
    const sums = parseChecksums(fs.readFileSync(argv[1], 'utf8'));
    const pins = {};
    for (const a of Object.values(TARGETS).sort()) {
      if (!sums[a]) fail(`REFUSING: ${argv[1]} has no digest for ${a}`);
      pins[a] = sums[a];
    }
    pkg.whisperCliDigests = pins;
    fs.writeFileSync(PKG_PATH, `${JSON.stringify(pkg, null, 2)}\n`);
    process.stderr.write(`pin-digests: pinned ${Object.keys(pins).length} digests for v${pkg.whisperCliVersion}\n`);
    return;
  }
  fail('usage: node pin-digests.js --write <checksums.txt> | --check');
}

if (require.main === module) main(process.argv.slice(2));
else module.exports = { parseChecksums, problems };
