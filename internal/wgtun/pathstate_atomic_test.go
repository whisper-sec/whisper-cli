// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package wgtun

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// hammerPublish rewrites one record in a loop while a second goroutine reads it, and returns
// the first read that could not be parsed. The two payloads differ in size by three orders of
// magnitude on purpose: the window a truncating write leaves open is proportional to how long
// the write takes, and a reader is only ever going to catch a window that is actually there.
//
// A read of a file that does not exist yet is not a tear, so it is skipped. Everything else is:
// an empty file, a prefix, or anything else that will not unmarshal is exactly what a surface
// in another process would have shown a person.
func hammerPublish(t *testing.T, write func(path string, b []byte) error) error {
	t.Helper()
	path := filepath.Join(t.TempDir(), "2a04_2a01_4__9.json")

	small, err := json.Marshal(map[string]any{"address": "2a04:2a01:4::9", "pid": 1})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	large, err := json.Marshal(map[string]any{
		"address": "2a04:2a01:4::9", "pid": 1, "pad": strings.Repeat("p", 1<<20),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			body := small
			if i%2 == 1 {
				body = large
			}
			if werr := write(path, body); werr != nil {
				return
			}
		}
	}()

	var torn error
	deadline := time.Now().Add(10 * time.Second)
	for torn == nil && time.Now().Before(deadline) {
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			if os.IsNotExist(rerr) {
				continue
			}
			torn = rerr
			break
		}
		var into map[string]any
		if uerr := json.Unmarshal(b, &into); uerr != nil {
			torn = uerr
		}
	}
	close(done)
	wg.Wait()
	return torn
}

// TestThePublishedRecordIsNeverReadableHalfWritten is the regression for the torn read that a
// loaded `go test ./...` caught once and then would not reproduce on demand.
//
// It carries its own control, and the control is the whole reason to trust it. A concurrency
// test that passes both before and after a fix has proven nothing about the window it claims
// to close, and this one would have been exactly that test: run it against os.WriteFile and it
// must FAIL, or the harness is not opening the window and its silence about the real writer
// means nothing.
func TestThePublishedRecordIsNeverReadableHalfWritten(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping the concurrent publish/read hammer in -short")
	}

	control := hammerPublish(t, func(path string, b []byte) error {
		return os.WriteFile(path, b, 0o600)
	})
	if control == nil {
		t.Fatal("control failed: a truncating os.WriteFile never tore under this harness, " +
			"so the harness is not opening the window and the assertion below proves nothing")
	}
	t.Logf("control: os.WriteFile tore as expected (%v)", control)

	if torn := hammerPublish(t, writePathRecord); torn != nil {
		t.Fatalf("writePathRecord published a record a reader could catch half-written: %v", torn)
	}
}
