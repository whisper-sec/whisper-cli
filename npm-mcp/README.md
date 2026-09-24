# Whisper MCP server

Give an AI agent a real, routable IPv6 identity, egress anyone can verify from outside,
and DNS policy you control. Plus the infrastructure graph, to ask "is this host safe?"
before connecting.

```json
{
  "mcpServers": {
    "whisper": {
      "command": "npx",
      "args": ["-y", "@whisper-security/whisper-mcp"]
    }
  }
}
```

That is the whole setup. Claude Desktop, Claude Code, Cursor, Windsurf, VS Code, Cline,
Zed: same three lines.

## It does something useful with no account

No key, no signup, 45 tools, real answers:

- `whisper_verify` - is this address or hostname a real Whisper agent, and whose?
- `whisper_rdap` - the IP-anchored registration record for a `/128`
- `explain_indicator` - one-call threat assessment for a domain, IP, ASN or hash
- `query` - Cypher against WhisperGraph, the internet's infrastructure graph
- `read_docs`, `list_workflows`, `run_workflow` - documentation and ready-made investigations

Add an API key and the same server also registers agents, sets resolver policy, hands out
egress configuration and reads your agents' activity. Nothing is hidden behind the key
that could have been answered without it.

## Getting a key

`https://whisper.online` - an email address, no human in the loop. Then either set
`WHISPER_API_KEY` in the server's `env` block, or run `whisper login`.

## What this package does

It resolves the `whisper` binary for your platform from the GitHub release tagged for
this exact package version, checks it against the `.sha256` published beside it, caches it,
and runs `whisper mcp`. The verified digest is recorded beside the binary and re-checked on
every run, so a given version of this package always resolves to the same bytes and a cached
copy that no longer matches the digest we recorded is never executed.

Already have the CLI (`brew install whisper-sec/tap/whisper`, `apt install whisper`,
`scoop install whisper`)? Then `whisper mcp` is the same server and you do not need this
package at all.

## Supported platforms

linux (amd64, arm64, arm, 386, riscv64, mips, mipsle), darwin (amd64, arm64),
windows (amd64, arm64).

## Links

- [whisper.online](https://whisper.online)
- [Source](https://github.com/whisper-sec/whisper-cli)
- [Issues](https://github.com/whisper-sec/whisper-cli/issues)

MIT.
