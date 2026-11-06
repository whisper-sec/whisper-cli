'use strict';

// npm test, or node --test test/wrapper.test.js (from npm-mcp/). Hermetic: no network, a fake CLI in a private cache.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const W = require('../bin/whisper-mcp.js');
const P = require('../pin-digests.js');
const PKG = require('../package.json');

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');
const A = 'a'.repeat(64);
const B = 'b'.repeat(64);
const C = 'c'.repeat(64);

test('--version goes straight to the CLI, everything else to `whisper mcp`', () => {
  assert.deepEqual(W.cliArgs(['--version']), ['--version']);
  assert.deepEqual(W.cliArgs([]), ['mcp']);
  assert.deepEqual(W.cliArgs(['--help']), ['mcp', '--help']);
  assert.deepEqual(W.cliArgs(['--version', '--json']), ['mcp', '--version', '--json']);
  assert.deepEqual(W.cliArgs(['-v']), ['mcp', '-v']);
});

test('the pinned digest decides, the published one only explains', () => {
  assert.equal(W.judgePinned(A, A, ''), null);
  assert.equal(W.judgePinned(A, A, B), null, 'a match on the pin passes whatever the sidecar says');
  const replaced = W.judgePinned(B, A, B).join('\n');
  assert.match(replaced, /CHECKSUM MISMATCH/);
  assert.match(replaced, new RegExp(`pinned by this package  ${A}`));
  assert.match(replaced, /REPLACED/);
  assert.match(W.judgePinned(B, A, A).join('\n'), /damaged or substituted/);
  assert.match(W.judgePinned(B, A, C).join('\n'), /matches neither/);
  assert.doesNotMatch(W.judgePinned(B, A, '').join('\n'), /published beside it/);
});

test('parseSum takes the first field and nothing that is not a digest', () => {
  assert.equal(W.parseSum(`${A.toUpperCase()}  whisper-linux-amd64\n`), A);
  assert.equal(W.parseSum('not-a-digest  x'), '');
  assert.equal(W.parseSum(''), '');
});

test('the committed package pins every asset the wrapper can fetch', () => {
  assert.deepEqual(P.problems(PKG.whisperCliDigests), []);
  assert.deepEqual(Object.keys(PKG.whisperCliDigests).sort(), Object.values(W.TARGETS).sort());
});

test('pin-digests refuses an incomplete, malformed or padded pin set', () => {
  const full = Object.fromEntries(Object.values(W.TARGETS).map((a) => [a, A]));
  assert.deepEqual(P.problems(full), []);
  assert.match(P.problems(undefined)[0], /no whisperCliDigests/);
  const missing = { ...full };
  delete missing['whisper-darwin-arm64'];
  assert.deepEqual(P.problems(missing), ['no digest pinned for whisper-darwin-arm64']);
  assert.match(P.problems({ ...full, 'whisper-linux-amd64': 'xyz' })[0], /not a lowercase sha256/);
  assert.match(P.problems({ ...full, 'whisper-plan9-386': A })[0], /never fetches it/);
  assert.deepEqual(P.parseChecksums(`${A}  one\n\n${B} *two\n`), { one: A, two: B });
});

/** A packed copy of this package with the given pins, plus a cache holding a fake CLI. */
function packedWith(pinFor) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'whisper-mcp-test-'));
  const tgz = execFileSync('npm', ['pack', '--silent', '--pack-destination', tmp], { cwd: ROOT, encoding: 'utf8' }).trim().split('\n').pop();
  execFileSync('tar', ['xzf', path.join(tmp, tgz), '-C', tmp]);
  const pkgDir = path.join(tmp, 'package');
  const fake = Buffer.from(`#!/bin/sh\necho "whisper version ${PKG.whisperCliVersion} ($*)"\n`);
  const pj = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
  pj.whisperCliDigests = Object.fromEntries(Object.values(W.TARGETS).map((a) => [a, pinFor(sha(fake))]));
  fs.writeFileSync(path.join(pkgDir, 'package.json'), JSON.stringify(pj));
  const cache = path.join(tmp, 'cache');
  const dir = path.join(cache, 'whisper-mcp', PKG.whisperCliVersion);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(dir, 'whisper'), fake, { mode: 0o700 });
  fs.writeFileSync(path.join(dir, 'whisper.sha256'), `${sha(fake)}\n`);
  return { tmp, pkgDir, cache };
}

const posix = process.platform !== 'win32';

test('the packed tarball answers --version with both versions', { skip: !posix }, () => {
  const { tmp, pkgDir, cache } = packedWith((d) => d);
  try {
    const r = spawnSync(process.execPath, [path.join(pkgDir, 'bin', 'whisper-mcp.js'), '--version'], {
      env: { ...process.env, WHISPER_MCP_CACHE: cache }, encoding: 'utf8',
    });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, new RegExp(`^whisper-mcp ${PKG.version} \\(runs the Whisper CLI ${PKG.whisperCliVersion}\\)\n`));
    assert.match(r.stdout, new RegExp(`whisper version ${PKG.whisperCliVersion} \\(--version\\)`));
    const m = spawnSync(process.execPath, [path.join(pkgDir, 'bin', 'whisper-mcp.js'), '--help'], {
      env: { ...process.env, WHISPER_MCP_CACHE: cache }, encoding: 'utf8',
    });
    assert.match(m.stdout, /\(mcp --help\)/, 'every other invocation keeps the mcp prefix');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('a pin set missing this platform refuses before running anything', { skip: !posix }, () => {
  const { tmp, pkgDir, cache } = packedWith(() => 'not-a-digest');
  try {
    const r = spawnSync(process.execPath, [path.join(pkgDir, 'bin', 'whisper-mcp.js'), '--version'], {
      env: { ...process.env, WHISPER_MCP_CACHE: cache }, encoding: 'utf8',
    });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /pins no valid sha256/);
    assert.doesNotMatch(r.stdout, /whisper version/, 'the cached binary must not run');
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('npm pack refuses a package that pins nothing', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'whisper-mcp-pack-'));
  try {
    for (const f of ['package.json', 'pin-digests.js', 'README.md', 'LICENSE']) fs.copyFileSync(path.join(ROOT, f), path.join(tmp, f));
    fs.mkdirSync(path.join(tmp, 'bin'));
    fs.copyFileSync(path.join(ROOT, 'bin', 'whisper-mcp.js'), path.join(tmp, 'bin', 'whisper-mcp.js'));
    const pj = JSON.parse(fs.readFileSync(path.join(tmp, 'package.json'), 'utf8'));
    delete pj.whisperCliDigests;
    fs.writeFileSync(path.join(tmp, 'package.json'), JSON.stringify(pj));
    const r = spawnSync('npm', ['pack', '--dry-run'], { cwd: tmp, encoding: 'utf8' });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /REFUSING: package.json has no whisperCliDigests/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
