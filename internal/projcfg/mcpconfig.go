// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// mcpconfig.go performs the surgical merge of a single MCP server entry into a client's
// PLAIN-JSON config file (`whisper mcp install`). It is conservative in exactly the way the
// Claude-settings merge is: read the existing JSON into a generic map, set ONLY our one server
// under the given top-level key, and write everything else back unchanged — a user's other MCP
// servers and settings survive untouched. It is used ONLY for clients whose config is strict
// JSON with an object-map of servers (project `.mcp.json` and `.cursor/mcp.json`, both keyed
// `mcpServers`); JSONC clients (VS Code, Zed) and YAML clients (Goose, Continue) are handled by
// printing a verified snippet instead, because a JSON round-trip would strip their comments or
// corrupt their format.

// MCPMergeResult reports what MergeJSONServer did, for an honest summary.
type MCPMergeResult struct {
	Created   bool // the config file did not exist and we created it
	Replaced  bool // an entry of the same name already existed and we updated it
	WrotePath string
}

// MergeJSONServer merges a server entry named `name` under top-level object key `topKey` in the
// strict-JSON file at `path`, creating the file (and its skeleton) if absent. It NEVER clobbers
// other keys/servers, refuses to write through a symlink, and writes atomically. A present but
// invalid-JSON file is a clear error (we refuse to plough on and destroy it).
func MergeJSONServer(path, topKey, name string, entry map[string]any) (MCPMergeResult, error) {
	res := MCPMergeResult{WrotePath: path}

	if err := refuseSymlink(path); err != nil {
		return res, err
	}

	root := map[string]any{}
	if b, err := os.ReadFile(path); err == nil {
		if len(strings.TrimSpace(string(b))) > 0 {
			if uerr := json.Unmarshal(b, &root); uerr != nil {
				return res, fmt.Errorf("%s is not valid JSON — fix or remove it, then re-run: %w", path, uerr)
			}
		}
	} else if os.IsNotExist(err) {
		res.Created = true
	} else {
		return res, fmt.Errorf("could not read %s: %w", path, err)
	}

	servers, _ := root[topKey].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	if _, existed := servers[name]; existed {
		res.Replaced = true
	}
	servers[name] = entry
	root[topKey] = servers

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return res, err
	}
	out = append(out, '\n')
	if err := writeFileAtomic(path, out, 0o644); err != nil {
		return res, err
	}
	return res, nil
}
