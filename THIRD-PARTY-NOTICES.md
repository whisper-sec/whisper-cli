# Third-party notices

The `whisper` CLI is licensed under the MIT License (see `LICENSE`). The published
binaries also embed and link the third-party material below, each under its own licence.

This file is generated from a built binary (`go version -m` for the linked modules, the
rule files' own provenance headers for the embedded corpora), so it describes what the
release actually ships rather than what anyone remembered to add.

## Embedded data

### Mozilla CA certificate list

- File: `internal/client/cabundle/mozilla-cacert.pem`
- The set of trust roots published by Mozilla (not Whisper-authored).
- Licence: Mozilla Public License 2.0 (MPL-2.0) - https://www.mozilla.org/MPL/2.0/

### Sigma detection rules (79 files)

- Directory: `internal/sensor/sigmarules/`
- 34 are bundled from SigmaHQ (https://github.com/SigmaHQ/sigma); 45 are
  first-party Whisper Security rules released under the same licence.
- Licence: Detection Rule License (DRL) 1.1 -
  https://github.com/SigmaHQ/Detection-Rule-License
- DRL 1.1 permits commercial use, redistribution in a commercial product and sale. Its
  obligation is attribution, and every rule carries its own `author:`, `references:` and,
  where adapted, a header stating what was changed and why (DRL 1.1 section 3(a)). Those
  headers travel inside the binary.

### YARA rules

- Directory: `internal/sensor/yararules/`
- `apt_lnx_kobalos.yar` - from ESET (https://github.com/eset/malware-ioc), BSD 2-Clause,
  upstream copyright retained in the file.
- `gen_lnx_malware_indicators.yar`, `mal_lnx_plague.yar` - bundled verbatim from
  https://github.com/Neo23x0/signature-base, Detection Rule License (DRL) 1.1.
- `eicar.yar` - first-party Whisper Security self-test rule, MIT. Listed here because it
  matches the standard EICAR anti-malware test string (https://www.eicar.org), which is not
  ours; the rule that matches it is.

## Linked Go modules (45)

| Module | Version | Licence |
| --- | --- | --- |
| `github.com/BobuSumisu/aho-corasick` | v1.0.3 | MIT |
| `github.com/PaesslerAG/gval` | v1.0.0 | BSD-3-Clause |
| `github.com/PaesslerAG/jsonpath` | v0.1.1 | BSD-3-Clause |
| `github.com/alecthomas/participle` | v0.7.1 | MIT |
| `github.com/atotto/clipboard` | v0.1.4 | BSD-3-Clause |
| `github.com/aymanbagabas/go-osc52/v2` | v2.0.1 | MIT |
| `github.com/bradleyjkemp/sigma-go` | v0.6.6 | MIT |
| `github.com/catppuccin/go` | v0.3.0 | MIT |
| `github.com/charmbracelet/bubbles` | v1.0.0 | MIT |
| `github.com/charmbracelet/bubbletea` | v1.3.10 | MIT |
| `github.com/charmbracelet/colorprofile` | v0.4.1 | MIT |
| `github.com/charmbracelet/huh` | v1.0.0 | MIT |
| `github.com/charmbracelet/lipgloss` | v1.1.0 | MIT |
| `github.com/charmbracelet/x/ansi` | v0.11.6 | MIT |
| `github.com/charmbracelet/x/cellbuf` | v0.0.15 | MIT |
| `github.com/charmbracelet/x/exp/strings` | v0.0.0-20240722160745-212f7b056ed0 | MIT |
| `github.com/charmbracelet/x/term` | v0.2.2 | MIT |
| `github.com/cilium/ebpf` | v0.22.0 | MIT |
| `github.com/clipperhouse/displaywidth` | v0.9.0 | MIT |
| `github.com/clipperhouse/stringish` | v0.1.1 | MIT |
| `github.com/clipperhouse/uax29/v2` | v2.5.0 | MIT |
| `github.com/cloudflare/circl` | v1.6.4 | BSD-3-Clause |
| `github.com/dustin/go-humanize` | v1.0.1 | MIT |
| `github.com/google/btree` | v1.1.2 | Apache-2.0 |
| `github.com/kardianos/service` | v1.3.0 | Zlib |
| `github.com/lucasb-eyer/go-colorful` | v1.3.0 | MIT |
| `github.com/mattn/go-isatty` | v0.0.20 | MIT |
| `github.com/mattn/go-runewidth` | v0.0.19 | MIT |
| `github.com/miekg/dns` | v1.1.72 | BSD-3-Clause |
| `github.com/mitchellh/hashstructure/v2` | v2.0.2 | MIT |
| `github.com/muesli/ansi` | v0.0.0-20230316100256-276c6243b2f6 | MIT |
| `github.com/muesli/cancelreader` | v0.2.2 | MIT |
| `github.com/muesli/termenv` | v0.16.0 | MIT |
| `github.com/rivo/uniseg` | v0.4.7 | MIT |
| `github.com/smallstep/pkcs7` | v0.2.3 | MIT (vendors BSD-3-Clause) |
| `github.com/spf13/cobra` | v1.10.2 | Apache-2.0 |
| `github.com/spf13/pflag` | v1.0.10 | BSD-3-Clause |
| `github.com/xo/terminfo` | v0.0.0-20220910002029-abceb7e1c41e | MIT |
| `golang.org/x/crypto` | v0.56.0 | BSD-3-Clause |
| `golang.org/x/net` | v0.58.0 | BSD-3-Clause |
| `golang.org/x/sys` | v0.47.0 | BSD-3-Clause |
| `golang.org/x/time` | v0.7.0 | BSD-3-Clause |
| `golang.zx2c4.com/wireguard` | v0.0.0-20260522210424-ecfc5a8d5446 | MIT |
| `gopkg.in/yaml.v3` | v3.0.1 | Apache-2.0 AND MIT |
| `gvisor.dev/gvisor` | v0.0.0-20250503011706-39ed1f5ac29c | Apache-2.0 AND MIT |
