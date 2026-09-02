---
name: whisper-identity
description: Give this agent a real, routable IPv6 identity and safe egress with one command. Use when an agent needs a stable source IP, reverse-DNS identity, or to route its traffic through a controlled network - for any framework (Python, Node), Claude Code, or a plain shell command.
license: MIT
homepage: https://whisper.online
---

# Whisper identity & egress

Whisper gives an agent its own routable IPv6 `/128` on real address space (AS219419):
a stable source IP, reverse-DNS identity, and a local proxy its traffic leaves from.
One small CLI does everything; no root, standard ports.

## 1. Install

```sh
curl -fsSL https://get.whisper.online | sh
# or:  brew install whisper-sec/tap/whisper
```

## 2. Authenticate (once)

Get a key from https://whisper.online, then:

```sh
export WHISPER_API_KEY="whisper_live_xxx"   # your key
whisper login                                # or rely on the env var
```

## 3. Give the current project an identity

Pick the one that matches what you're running - each wires the working directory so
traffic egresses from the project's `/128`:

```sh
whisper init python    # any Python agent framework (httpx/requests): LangChain, CrewAI, …
whisper init claude    # Claude Code (and every subagent it spawns)
```

Then run normally:

```sh
whisper run python script.py      # zero-config, all platforms
# or, after `whisper init python`, activate the printed env and run `python script.py`
```

## 4. Run any one-off command through the identity

No project setup needed:

```sh
whisper run curl -s https://api64.ipify.org      # prints your Whisper /128
```

## Verify

```sh
whisper run curl -s https://api64.ipify.org
# → a 2a04:2a01:…  address (your agent's identity), not your host IP
```

## Notes

- The proxy serves both HTTP-CONNECT and SOCKS5 on a local loopback port; most clients
  pick it up from `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` automatically.
- `aiohttp` ignores proxy env by default - pass `ClientSession(trust_env=True)`.
- Docs: https://whisper.online · CLI source (MIT): https://github.com/whisper-sec/whisper-cli

_This file is served from the repository it lives in. Everything it tells you to install is
verified where it matters: every published `whisper` binary carries a detached PGP signature
made with the AS219419 release key (fingerprint `EFF1663D992539682106A5EAD0F70908CF3B7929`),
and the installer checks it._
