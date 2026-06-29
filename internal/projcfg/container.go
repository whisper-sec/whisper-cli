// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package projcfg

import (
	"fmt"
	"os"
	"path/filepath"
)

// container.go emits the wholly-owned container manifests `whisper init compose` and
// `whisper init k8s` write under .whisper/ — a Whisper egress SIDECAR plus the app-side proxy env.
// The sidecar runs the official image (ghcr.io/whisper-sec/whisper) as `whisper connect`, binding
// the local proxy on the deterministic port; the app shares the sidecar's network namespace
// (compose `network_mode: service:whisper`; k8s same Pod) so it reaches the proxy on
// 127.0.0.1:<port> via the standard proxy env (the same .whisper/proxy.env WriteProxyEnv writes).
//
// Like every init target these files live ONLY under .whisper/ (clobber-safe, never the user's own
// docker-compose.yml / manifests) — they are overlays the user composes in, not edits to their files.

// ContainerImage is the official multi-arch image the sidecar runs (#198).
const ContainerImage = "ghcr.io/whisper-sec/whisper:latest"

// WriteComposeSidecar writes .whisper/compose.yml — a Docker Compose overlay with a `whisper`
// egress sidecar bound to cfg.Port, to be merged alongside the user's compose:
//
//	docker compose -f docker-compose.yml -f .whisper/compose.yml up
//
// When service != "" an example app service wired to the sidecar (shared netns + proxy env) is
// emitted too; otherwise the user adds `network_mode: "service:whisper"` + `env_file:
// [.whisper/proxy.env]` to their own service. Atomic + symlink-safe.
func WriteComposeSidecar(p Paths, cfg Config, service string) (Created bool, err error) {
	path := composePath(p)
	if err := refuseSymlink(path); err != nil {
		return false, err
	}
	created := !exists(path)
	if err := writeFileAtomic(path, []byte(composeContent(cfg, service)), 0o600); err != nil {
		return false, err
	}
	return created, nil
}

// WriteK8sSidecar writes .whisper/whisper-sidecar.yaml — a strategic-merge patch adding a NATIVE
// sidecar (an initContainer with restartPolicy: Always, k8s >= 1.29) plus the app-side proxy env,
// to be applied over a Deployment/Pod spec. Atomic + symlink-safe.
func WriteK8sSidecar(p Paths, cfg Config) (Created bool, err error) {
	path := k8sPath(p)
	if err := refuseSymlink(path); err != nil {
		return false, err
	}
	created := !exists(path)
	if err := writeFileAtomic(path, []byte(k8sContent(cfg)), 0o600); err != nil {
		return false, err
	}
	return created, nil
}

func composeContent(cfg Config, service string) string {
	port := cfg.Port
	agent := cfg.Agent
	s := "# whisper-managed — `whisper init compose`. A Whisper egress sidecar; merge it alongside\n" +
		"# your compose:  docker compose -f docker-compose.yml -f .whisper/compose.yml up\n" +
		"# Give the app service that should egress:  network_mode: \"service:whisper\"  +  env_file: [.whisper/proxy.env]\n" +
		"# Export WHISPER_API_KEY in your shell first (it is read from the environment, never written here).\n" +
		"services:\n" +
		"  whisper:\n" +
		fmt.Sprintf("    image: %s\n", ContainerImage) +
		fmt.Sprintf("    command: [\"connect\", \"--agent\", %q, \"--port\", %q]\n", agent, fmt.Sprintf("%d", port)) +
		"    environment:\n" +
		"      WHISPER_API_KEY: ${WHISPER_API_KEY:?export WHISPER_API_KEY before composing}\n" +
		"    restart: unless-stopped\n"
	if service != "" {
		s += fmt.Sprintf("  %s:\n", service) +
			"    # your app — set its image/build; it egresses through the sidecar's /128.\n" +
			"    # image: your-app:latest\n" +
			"    network_mode: \"service:whisper\"\n" +
			"    env_file: [.whisper/proxy.env]\n" +
			"    depends_on: [whisper]\n"
	}
	return s
}

func k8sContent(cfg Config) string {
	port := cfg.Port
	ep := fmt.Sprintf("http://127.0.0.1:%d", port)
	socks := fmt.Sprintf("socks5h://127.0.0.1:%d", port)
	return "# whisper-managed — `whisper init k8s`. A NATIVE sidecar (initContainer restartPolicy: Always,\n" +
		"# Kubernetes >= 1.29) that egresses the Pod through a Whisper /128. Merge into your\n" +
		"# Deployment/Pod spec (spec.template.spec) and set the app container name + the WHISPER_API_KEY secret:\n" +
		"#   kubectl create secret generic whisper --from-literal=api-key=whisper_live_xxx\n" +
		"spec:\n" +
		"  template:\n" +
		"    spec:\n" +
		"      initContainers:\n" +
		"        - name: whisper\n" +
		fmt.Sprintf("          image: %s\n", ContainerImage) +
		"          restartPolicy: Always   # native sidecar: starts first, runs for the Pod's life\n" +
		fmt.Sprintf("          args: [\"connect\", \"--agent\", %q, \"--port\", %q]\n", cfg.Agent, fmt.Sprintf("%d", port)) +
		"          env:\n" +
		"            - name: WHISPER_API_KEY\n" +
		"              valueFrom:\n" +
		"                secretKeyRef: { name: whisper, key: api-key }\n" +
		"      containers:\n" +
		"        - name: YOUR-APP-CONTAINER   # <- set to your app container's name\n" +
		"          env:\n" +
		fmt.Sprintf("            - { name: HTTP_PROXY,  value: %q }\n", ep) +
		fmt.Sprintf("            - { name: HTTPS_PROXY, value: %q }\n", ep) +
		fmt.Sprintf("            - { name: ALL_PROXY,   value: %q }\n", socks) +
		"            - { name: NO_PROXY, value: \"localhost,127.0.0.1,::1,.svc,.cluster.local\" }\n"
}

func composePath(p Paths) string { return filepath.Join(p.WhisperDir, "compose.yml") }
func k8sPath(p Paths) string     { return filepath.Join(p.WhisperDir, "whisper-sidecar.yaml") }

// exists reports whether path is present (a missing file ⇒ false; any other stat result ⇒ true).
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
