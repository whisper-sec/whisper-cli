# whisper

**Give your agent a real, routable Whisper IPv6 identity - one command.**

`whisper` is the command-line client for [Whisper](https://whisper.online): a single
static binary that gives an agent a real, routable IPv6 `/128` on **AS219419**, wires
egress so the agent's traffic sources *from* that address, and verifies it end-to-end.
The address *is* the identity - DNSSEC-signed, DANE-pinned, and resolvable in public
[RDAP](https://rdap.whisper.online). One binary, standard ports, no config to get
started.

It is two surfaces over one core: a fully scriptable [Cobra](https://github.com/spf13/cobra)
CLI, and a full-screen [Bubble Tea](https://github.com/charmbracelet/bubbletea) TUI when
you run `whisper` on a terminal with no subcommand. And it talks to the
[whisper.security](https://www.whisper.security) graph: `whisper query` for raw Cypher,
`whisper graph` for the 29-recipe catalog ([below](#query-the-security-graph)).

---

## Install

The one-liner fetches the signed binary straight from this repo's **GitHub Releases**,
verifies its SHA-256 (and its PGP signature when `gpg` is present), and puts it on your
`PATH`:

```sh
curl -fsSL https://get.whisper.online | sh
```

Windows (PowerShell):

```powershell
irm https://get.whisper.online/install.ps1 | iex
```

Homebrew (macOS/Linux):

```sh
brew install whisper-sec/tap/whisper
```

Scoop (Windows):

```powershell
scoop bucket add whisper https://github.com/whisper-sec/scoop-bucket
scoop install whisper
```

With Go:

```sh
go install github.com/whisper-sec/whisper-cli/cmd/whisper@latest
```

With [mise](https://mise.jdx.dev) (GitHub-release backend, no plugin):

```sh
mise use -g "github:whisper-sec/whisper-cli[exe=whisper]"
```

(asdf has no built-in GitHub-release backend, so on asdf use mise, or a community
`ubi`-style plugin.)

On Debian/Ubuntu (apt) - signed repo:

```sh
curl -fsSL https://get.whisper.online/whisper.gpg | sudo tee /usr/share/keyrings/whisper.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/whisper.gpg] https://get.whisper.online/deb stable main" | sudo tee /etc/apt/sources.list.d/whisper.list
sudo apt update && sudo apt install whisper
```

On Fedora/RHEL (dnf) - signed repo:

```sh
sudo tee /etc/yum.repos.d/whisper.repo >/dev/null <<'EOF'
[whisper]
name=Whisper
baseurl=https://get.whisper.online/rpm
enabled=1
gpgcheck=1
gpgkey=https://get.whisper.online/whisper.gpg
EOF
sudo dnf install whisper
```

On Alpine (apk) - signed repo:

```sh
wget -qO /etc/apk/keys/whisper-apk.rsa.pub https://get.whisper.online/apk/whisper-apk.rsa.pub
echo "https://get.whisper.online/apk" | sudo tee -a /etc/apk/repositories
sudo apk add whisper
```

All three repos are served from our own infrastructure (AS219419) and signed with the
Whisper package key (`get.whisper.online/whisper.gpg`; the apk repo uses its own
`whisper-apk.rsa.pub`).

Or download the binary for your platform from the
[Releases page](https://github.com/whisper-sec/whisper-cli/releases/latest), make it
executable, and put it on your `PATH`.

> The installers (`scripts/install.sh`, `scripts/install.ps1`) are published here so the
> whole install path is inspectable. They are the same scripts `get.whisper.online` serves,
> differing only in where they download from by default: these fetch
> `whisper-<os>-<arch>` (plus `.sha256` and `.asc`) from this repo's releases, the served
> copy fetches the same binaries from `cli.whisper.online/dl`. Either way SHA-256 is a hard
> gate - a mismatch aborts the install - and the PGP check is an extra layer. Point
> `WHISPER_CLI_BASE` at any mirror to override the source.

### Verify the download

Releases are signed with the **AS219419** PGP key:

```
Fingerprint: EFF1663D992539682106A5EAD0F70908CF3B7929
```

The public key is published at <https://as219419.net/>. To verify a binary you
downloaded manually:

```sh
# 1. SHA-256 - compare against the asset's .sha256 (and the release checksums.txt)
sha256sum -c whisper-linux-amd64.sha256

# 2. PGP - import the AS219419 key, then verify the detached signature
curl -fsSL https://as219419.net/whisper-release.asc | gpg --import
gpg --verify whisper-linux-amd64.asc whisper-linux-amd64
```

A good signature reports `Good signature` from the key with the fingerprint above.

---

## Quickstart

Run `whisper` with no arguments for the guided flow. It signs you in (browser device
login or a pasted API key), helps you name and create an agent if you don't have one,
then connects and verifies:

```text
$ whisper
whisper: signed in.
whisper: name your agent: my-first-agent
whisper: created my-first-agent → 2a04:2a01:…::1
whisper: connecting…
2a04:2a01:…::1  ✓ egress verified
Connected ✓
```

Naming is mandatory - an agent's name is part of its identity, so the flow asks before
it creates one. The same steps are scriptable:

```sh
whisper connect            # bring up egress bound to your /128 (Tier-1.5 SOCKS5/HTTPS)
whisper connect --tier wireguard   # Tier-1: routed /128 over a userspace WireGuard tunnel (no root)
whisper ip                 # print your egress IP and verify it IS your /128 (exit 0 = verified)
whisper run -- curl ifconfig.co   # run any command with your Whisper egress wired in
whisper claude             # run Claude Code through your Whisper egress, one step
whisper init claude        # wire THIS project so Claude Code always egresses from its own /128
whisper use my-agent       # choose the agent the rest of `whisper` binds to
whisper status             # key state, selected agent, connection state
```

`whisper ip` is exit-code-first: `0` when the observed egress address is inside
`2a04:2a01::/32` *and* equals your selected agent's `/128`, `1` otherwise - so scripts
and agents can gate on it. Add `--json` to any command for the raw, scriptable envelope.

**Per-project agent identity for Claude Code.** `whisper init claude` makes a project
zero-config: run it once in a directory and Claude Code there - and every subagent it
spawns - egresses from that project's own `/128`, over SOCKS5 (default) or `--tier
wireguard`. It pins the project's agent + tier in `.whisper/config`, wires a local proxy
into `.claude/settings.local.json` (merge-safe - it never clobbers your settings), and
keeps the connection up via a small auto-reconnecting daemon. Different projects, different
identities, nothing to remember. Pass `--agent <name|/128>` to reuse an existing agent or
`--name <new>` to mint one.

Other useful commands: `whisper list`, `whisper logs`, `whisper policy`, `whisper rdap
<address>`, `whisper verify <address>`, `whisper query <cypher>`, `whisper graph
<recipe>`, `whisper login`, `whisper dash` (the full-screen dashboard), `whisper config`.
Run `whisper <command> --help` for details.

---

## Query the security graph

The same [whisper.security](https://www.whisper.security) graph the Whisper resolver
consults on every lookup - 7.4B nodes (hostnames, IPs, ASNs, certs, threat intel), 39B
relationships - is a first-class CLI surface. `whisper query` runs raw parameterised
Cypher; `whisper graph` runs a named recipe from the embedded catalog:

```sh
whisper query "CALL whisper.identify(['api.openai.com'])"    # who operates this host?
whisper query 'CALL whisper.assess([$v])' --param v=8.8.8.8  # threat posture, one row per host
whisper graph list                    # all 29 recipes, each with its docs URL
whisper graph variants paypal.com     # registered typosquat look-alikes, one table
whisper graph typosquat paypal.com    # the full brand-impersonation flow (streams NDJSON)
```

Direct recipes answer with one result table (`--json` emits the raw
`{columns,rows,statistics}` envelope); flow recipes stream their steps as NDJSON - pipe
them to `jq`. Every recipe documents itself: `whisper graph <recipe> --help`.

`query` and `graph` authenticate with your API key (`whisper login`, `WHISPER_API_KEY`,
or `--key`). The graph endpoint itself is two-tier: the direct read verbs
(`whisper.identify`, `whisper.assess`, `whisper.variants`, `whisper.explain`,
`db.schema`, ...) also answer keyless and rate-limited - no account needed:

```sh
curl -s https://graph.whisper.online/api/query \
  -H 'content-type: application/json' \
  -d '{"query":"CALL whisper.assess([\"8.8.8.8\"])"}'
```

A key lifts the rate limit and unlocks raw Cypher and the multi-step flows. The same
tools ride the MCP server (`whisper mcp`): `whisper_graph_query` plus one tool per
recipe. Docs: [www.whisper.security/docs](https://www.whisper.security/docs) - the raw
Cypher API at [/docs/cypher-api](https://www.whisper.security/docs/cypher-api), per-verb
pages under `/docs/whisper-graph`.

---

## Sign, verify & encrypt as your agent

Your agent's `/128` carries a per-agent EC P-256 key, pinned in DNSSEC-signed DNS - so it can **sign** a document as itself and anyone can **verify** it with no account and no certificate authority. Trust is anchored by DANE, not a CA you have to install.

```bash
# Sign any file, PDF or email as your agent -> a detached S/MIME (.p7s):
whisper sign file contract.pdf

# Verify with NO key: checks the CMS signature AND that the signer's key matches the
# DNSSEC-validated SMIMEA (RFC 8162) pin for the signer - resolved from the IANA root, in-process:
whisper sign verify contract.pdf --sig contract.pdf.p7s

# Encrypt a file so ONLY the named agent can read it (keyless), then decrypt as that agent (keyed):
whisper encrypt --to agent@a1b2c3.agents.whisper.online secret.txt   # -> secret.txt.wenc
whisper decrypt secret.txt.wenc
```

The **per-agent verification key** a stranger resolves is the agent's DANE `TLSA 3 1 1` (and, for signatures, its `SMIMEA 3 1 1`) - both DNSSEC-signed and checkable with `dig` + `openssl`, no Whisper account. Full guide, including the byte-exact signature envelope: <https://whisper.online/docs/sign-encrypt>.

## What you get

- **A real, routable `/128`** out of `2a04:2a01::/32`, announced by **AS219419** - your
  own internet address, not a shared NAT pool.
- **Identity that's verifiable from the outside.** Forward DNS is DNSSEC-signed and
  DANE-pinned; reverse DNS (`ip6.arpa` PTR) resolves to the agent; the assignment is
  visible in public RDAP at [rdap.whisper.online](https://rdap.whisper.online).
- **Egress that binds your identity.** `whisper connect` provisions a local proxy whose
  traffic sources *from* your `/128`; `whisper ip` proves the source address is yours,
  node-free and with no third party in the loop. `--tier wireguard` brings the `/128` up
  as a **routed** address over a userspace WireGuard tunnel (wireguard-go netstack - still
  no root, no kernel `wg`, no TUN device), fronted by the same local proxy so tools need
  no change.
- **One binary, zero config.** Static, CGO-free, with an embedded CA bundle - it runs on
  a bare host or a stripped container and just works.

---

## Use it from your code

Same identity + egress from your language of choice - thin wrappers over this CLI:

**Python** - `pip install whisper-id`

```python
from whisper_id import register, egress
agent = register("my-bot")            # a routable /128
with egress():                        # this block leaves from your /128
    requests.get("https://api64.ipify.org")
```

**Node** - `npm i whisper-id`

```js
import { register, withEgress } from "whisper-id";
const agent = await register("my-bot");
await withEgress(async () => { /* env-aware clients leave from your /128 */ });
```

## Run it in a container

The official image runs the CLI as an egress sidecar so any container leaves from your `/128`:

```sh
docker run --rm ghcr.io/whisper-sec/whisper:latest --version
```

`whisper init compose` and `whisper init k8s` emit a ready-to-merge sidecar manifest.
Multi-arch (amd64/arm64), distroless, ~18 MB.

---

## Build from source

Requires Go 1.25+.

```sh
git clone https://github.com/whisper-sec/whisper-cli
cd whisper-cli
go build -o whisper ./cmd/whisper
./whisper --version
```

Cross-compile every supported platform into `dist/` (binaries + `.sha256`, named exactly
as the release assets):

```sh
./build-all.sh                 # → dist/whisper-<os>-<arch>[.exe] + .sha256
./build-all.sh dist v1.0.0     # stamp a version into `whisper --version`
```

`platforms.txt` is the single source of truth for the target matrix - shared by
`build-all.sh` and the installers.

### Source here, binaries there

This repository is the Whisper **client**: identity, egress, connect, verify, the
security-graph surface and the TUI. It is MIT, and what you build from it is that client.

The published binaries are not only that. `whisper` also carries Whisper's **endpoint
sensor** - the `service`, `sensor` and `posture` commands - and the sensor is not open
source today. It ships as a binary and its sources stay closed, so a binary from a release,
from `curl -fsSL https://get.whisper.online | sh`, or from apt, dnf, apk, brew or scoop has those
commands. Anything BUILT from this tree does not: `go install`, a local `go build`, and the
snap, which snapcraft builds from source.

Two consequences worth stating plainly. The MIT licence covers the source in this
repository, not the additional closed component in the published binaries. And if you
want the endpoint sensor, install a released binary rather than building from source.

### Platforms

| OS \ Arch | amd64 | arm64 | arm | riscv64 | mips | mipsle | 386 |
|-----------|:-----:|:-----:|:---:|:-------:|:----:|:------:|:---:|
| linux     |   ✓   |   ✓   |  ✓  |    ✓    |  ✓   |   ✓    |  ✓  |
| darwin    |   ✓   |   ✓   |     |         |      |        |     |
| windows   |   ✓   |   ✓   |     |         |      |        |     |

`linux-arm` is 32-bit ARMv7. Every target is a static, CGO-free build, and every one is
signed with the AS219419 release key.

---

## Links

- **Whisper** - [whisper.online](https://whisper.online)
- **Docs (graph procedures, recipes, the Cypher API)** - [www.whisper.security/docs](https://www.whisper.security/docs)
- **Registry / NIC** - [nic.whisper.online](https://nic.whisper.online)
- **RDAP** - [rdap.whisper.online](https://rdap.whisper.online)
- **AS219419** (release-signing key, network info) - [as219419.net](https://as219419.net)

---

## Contributing

Issues and pull requests are welcome - see [CONTRIBUTING.md](CONTRIBUTING.md). Run
`go build ./...`, `go vet ./...`, `go test ./...`, and `gofmt -l .` before opening a PR.

To report a security issue, see [SECURITY.md](SECURITY.md).

---

## License

[MIT](LICENSE) © 2026 viaGraph B.V. (Whisper Security) - for the source in this
repository. The published binaries additionally contain the closed-source endpoint
sensor; see [Source here, binaries there](#source-here-binaries-there).

The embedded Mozilla CA certificate list
(`internal/client/cabundle/mozilla-cacert.pem`) is distributed under the Mozilla Public
License 2.0.
