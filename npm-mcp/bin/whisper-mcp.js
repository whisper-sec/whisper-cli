#!/usr/bin/env node
'use strict';

/*
 * `npx -y @whisper-security/whisper-mcp` - the Whisper MCP server, one command, no install.
 *
 * The server is a Go binary (`whisper mcp`). This wrapper exists so it can be run the way
 * MCP clients expect, with npx, by anyone who has not installed the CLI.
 *
 * THE ONE RULE THIS FILE MUST NEVER BREAK: stdout belongs to the MCP JSON-RPC stream.
 * A single stray byte on stdout corrupts the protocol and the client drops the connection,
 * which presents as "the server does not work" with nothing in any log. Every diagnostic
 * here goes to stderr, deliberately and without exception.
 *
 * TRUST. The binary is fetched from the GitHub release this package pins and checked against
 * the sha256 digest written into this package's own package.json (`whisperCliDigests`) when
 * it was published. An npm version is immutable, so a given version of this package always
 * resolves to the same bytes, even if somebody later replaces an asset under the release tag:
 * the replaced file does not match the pin and is refused. The `.sha256` published beside the
 * asset is read only to explain a mismatch. The verified digest is recorded next to the binary
 * and re-checked on EVERY run, so a cached copy that no longer matches it is never run.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');

const PKG = require('../package.json');
/*
 * The CLI release this wrapper resolves, which is NOT the wrapper's own version. They move
 * independently: a packaging fix bumps `version` while still fetching the same audited binary,
 * and a CLI release bumps `whisperCliVersion`. Deriving one from the other looked tidy and meant
 * that publishing a patch pointed the download at a release tag that did not exist.
 */
const CLI_VERSION = PKG.whisperCliVersion || PKG.version;
const VERSION = CLI_VERSION;
/*
 * The per-asset digests of that release, pinned at publish time from its checksums.txt by
 * pin-digests.js. A package without them (a local checkout, never a published one: the pack
 * refuses it) falls back to the `.sha256` beside the asset, which proves the download arrived
 * intact but not that the asset is the one that was released.
 */
const PINS = PKG.whisperCliDigests || null;
const REPO = 'whisper-sec/whisper-cli';
const BASE = `https://github.com/${REPO}/releases/download/v${CLI_VERSION}`;

/** stderr only. See the header: stdout is the protocol. */
function note(msg) {
  process.stderr.write(`whisper-mcp: ${msg}\n`);
}

function die(msg, hint) {
  process.stderr.write(`\nwhisper-mcp: ${msg}\n`);
  if (hint) process.stderr.write(`${hint}\n`);
  process.stderr.write('\n');
  process.exit(1);
}

/**
 * Our release assets are named by GOOS-GOARCH. Node spells several of those differently,
 * so the mapping is explicit rather than a string concat: an unknown pair must produce a
 * useful message naming what we DO ship, not a 404 the user has to decode.
 */
const TARGETS = {
  'linux-x64': 'whisper-linux-amd64',
  'linux-arm64': 'whisper-linux-arm64',
  'linux-arm': 'whisper-linux-arm',
  'linux-ia32': 'whisper-linux-386',
  'linux-riscv64': 'whisper-linux-riscv64',
  'linux-mips': 'whisper-linux-mips',
  'linux-mipsel': 'whisper-linux-mipsle',
  'darwin-x64': 'whisper-darwin-amd64',
  'darwin-arm64': 'whisper-darwin-arm64',
  'win32-x64': 'whisper-windows-amd64.exe',
  'win32-arm64': 'whisper-windows-arm64.exe',
};

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * The digest this package pins for an asset, or null when the package pins none. A package that
 * pins digests but not THIS one, or pins something that is not a sha256, was packed wrong, and
 * running an unpinned binary from it would be the exact hole the pins close, so that is fatal.
 */
function pinnedDigest(pins, asset) {
  if (!pins) return null;
  const d = typeof pins[asset] === 'string' ? pins[asset].toLowerCase() : '';
  if (!HEX64.test(d)) {
    die(
      `this package pins no valid sha256 for ${asset}, so the download cannot be verified.`,
      `  Nothing was executed. Please report this at https://github.com/${REPO}/issues`
    );
  }
  return d;
}

/**
 * Judge downloaded bytes against the pin. Returns null when they match, or the message and the
 * hint to die with. `published` is the `.sha256` beside the asset, fetched only now, to say
 * WHICH way it went wrong: a published checksum that names the bytes we got means the asset was
 * replaced under the tag after this package was published; one that names the pin means the
 * bytes were damaged or substituted on the way here.
 */
function judgePinned(got, pinned, published) {
  if (got === pinned) return null;
  let why;
  if (published === got) {
    why =
      `  The release now publishes a checksum for these new bytes, so the asset was REPLACED\n` +
      `  after this package version was published. This package will only run the bytes it pins.`;
  } else if (published === pinned) {
    why = `  The release still publishes the pinned digest, so the download was damaged or substituted on the way.`;
  } else {
    why = `  The checksum published beside the asset matches neither.`;
  }
  return [
    'CHECKSUM MISMATCH - refusing to run the downloaded binary.',
    `  pinned by this package  ${pinned}\n  downloaded             ${got}\n` +
      (published ? `  published beside it    ${published}\n` : '') +
      `${why}\n  Nothing was executed. Please report this at https://github.com/${REPO}/issues`,
  ];
}

/** The first field of a "<hex>  <name>" checksum file, lowercased; '' when it is not a digest. */
function parseSum(txt) {
  const d = String(txt).trim().split(/\s+/)[0].toLowerCase();
  return HEX64.test(d) ? d : '';
}

function assetName() {
  const key = `${process.platform}-${process.arch}`;
  const asset = TARGETS[key];
  if (!asset) {
    die(
      `no Whisper build for ${key}.`,
      `  We ship: ${Object.keys(TARGETS).join(', ')}\n` +
        `  If you need ${key}, please open an issue at https://github.com/${REPO}/issues`
    );
  }
  return asset;
}

function cacheDir() {
  // Honour XDG, fall back to the platform convention. Keyed by version so an upgrade
  // never reuses an older binary and a downgrade never has to re-download.
  const base =
    process.env.WHISPER_MCP_CACHE ||
    process.env.XDG_CACHE_HOME ||
    (process.platform === 'win32'
      ? process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local')
      : process.platform === 'darwin'
        ? path.join(os.homedir(), 'Library', 'Caches')
        : path.join(os.homedir(), '.cache'));
  return path.join(base, 'whisper-mcp', VERSION);
}

function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

async function fetchOrDie(url, what) {
  let res;
  try {
    res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(60_000) });
  } catch (e) {
    die(
      `could not reach the download host while fetching ${what}.`,
      `  ${url}\n  ${e && e.message ? e.message : e}\n` +
        `  If you are behind a proxy, set HTTPS_PROXY and try again.`
    );
  }
  if (!res.ok) {
    die(`${what} returned HTTP ${res.status}.`, `  ${url}`);
  }
  return Buffer.from(await res.arrayBuffer());
}

/**
 * Resolve the binary, downloading and verifying it once per version. Concurrent `npx` runs
 * are safe: each writes a unique temp file and renames it into place, and rename is atomic
 * on every platform we ship to.
 */
async function ensureBinary() {
  const asset = assetName();
  const dir = cacheDir();
  const exe = path.join(dir, process.platform === 'win32' ? 'whisper.exe' : 'whisper');
  const stamp = `${exe}.sha256`;

  // A cached binary is re-hashed against the digest we recorded when we verified it. Trusting
  // the cache because it exists would mean anyone who can write the cache path gets code
  // execution inside a process holding WHISPER_API_KEY in its environment. On a laptop that
  // path is private; under a shared XDG_CACHE_HOME or on CI it is not, and the check costs
  // about a tenth of a second.
  const pinned = pinnedDigest(PINS, asset);
  if (fs.existsSync(exe) && fs.existsSync(stamp)) {
    const recorded = fs.readFileSync(stamp, 'utf8').trim().slice(0, 64);
    // With a pin, the cached copy must be the pinned bytes, not merely the bytes recorded.
    if (HEX64.test(recorded) && (!pinned || recorded === pinned) && sha256(fs.readFileSync(exe)) === recorded) {
      return exe;
    }
    note('the cached binary no longer matches its recorded digest; fetching a clean copy');
    try {
      fs.rmSync(exe, { force: true });
      fs.rmSync(stamp, { force: true });
    } catch (e) {
      die(
        `the cached copy at ${exe} does not match its digest and could not be removed.`,
        `  ${e.message}\n  Delete that directory and run again.`
      );
    }
  }

  note(`fetching the Whisper CLI ${VERSION} for ${process.platform}-${process.arch} (first run only)`);
  const bin = await fetchOrDie(`${BASE}/${asset}`, 'the binary');
  const got = sha256(bin);
  if (pinned) {
    if (got !== pinned) {
      // Best effort: the explanation must never mask the refusal, so a failed fetch is ''.
      let published = '';
      try {
        const res = await fetch(`${BASE}/${asset}.sha256`, { redirect: 'follow', signal: AbortSignal.timeout(20_000) });
        if (res.ok) published = parseSum(await res.text());
      } catch (_) {
        published = '';
      }
      die(...judgePinned(got, pinned, published));
    }
  } else {
    const want = parseSum(await fetchOrDie(`${BASE}/${asset}.sha256`, 'its checksum'));
    if (!want) {
      die('the published checksum is not a sha256 digest, so the download cannot be verified.');
    }
    if (got !== want) {
      die(
        'CHECKSUM MISMATCH - refusing to run the downloaded binary.',
        `  expected ${want}\n  got      ${got}\n` +
          `  Nothing was executed. Please report this at https://github.com/${REPO}/issues`
      );
    }
  }

  // 0o700 on the directory too, not just the file: a group-writable cache directory hands the
  // same code execution to anyone who can create a file in it, whatever the binary's own mode.
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  // A random name with an exclusive-create flag. A predictable one is a symlink target someone
  // can pre-place, and writeFileSync would follow it and write wherever it points.
  const tmp = path.join(dir, `.whisper.${crypto.randomBytes(8).toString('hex')}.part`);
  fs.writeFileSync(tmp, bin, { flag: 'wx', mode: 0o700 });
  fs.renameSync(tmp, exe);
  fs.writeFileSync(stamp, `${got}\n`, { mode: 0o600 });
  note(`verified sha256 ${got.slice(0, 16)}... and cached at ${exe}`);
  return exe;
}

/**
 * The CLI arguments for what the caller typed. The server is the default, so everything is
 * passed to `whisper mcp`, with one exception: `--version` asks which CLI this package runs,
 * and `whisper mcp --version` is an unknown flag. That one goes straight to the CLI.
 * `--help` keeps the prefix on purpose: `whisper mcp --help` is the help for the server, which
 * is what someone running whisper-mcp is asking for.
 */
function cliArgs(argv) {
  if (argv.length === 1 && argv[0] === '--version') return ['--version'];
  return ['mcp', ...argv];
}

async function main() {
  const argv = process.argv.slice(2);
  const args = cliArgs(argv);
  if (args[0] === '--version') {
    // Not the MCP stream, so stdout is right here: this is what a person or a script reads.
    process.stdout.write(`whisper-mcp ${PKG.version} (runs the Whisper CLI ${CLI_VERSION})\n`);
  }
  const exe = await ensureBinary();

  const child = spawn(exe, args, { stdio: 'inherit', env: process.env });

  // Forward the signals a client uses to stop us, so the server shuts down cleanly
  // instead of being orphaned when the MCP client goes away.
  const SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];
  for (const sig of SIGNALS) {
    process.on(sig, () => {
      if (!child.killed) child.kill(sig);
    });
  }
  child.on('error', (e) => die(`could not start the Whisper CLI: ${e.message}`));
  child.on('exit', (code, signal) => {
    if (signal) {
      // Report the child's death the way a shell would, by dying the same way. Our own
      // handlers above have to come off first: otherwise this re-raise is caught by them,
      // turned into a kill of an already-dead child, and swallowed into exit 0.
      for (const s of SIGNALS) process.removeAllListeners(s);
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code === null ? 1 : code);
  });
}

// Required as a module (by pin-digests.js and the tests) it only exports; run, it runs.
if (require.main === module) {
  main().catch((e) => die(e && e.stack ? e.stack : String(e)));
} else {
  module.exports = { TARGETS, HEX64, cliArgs, judgePinned, parseSum, pinnedDigest };
}
