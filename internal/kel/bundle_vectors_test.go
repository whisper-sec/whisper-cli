// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package kel

import (
	"strconv"
	"strings"
	"testing"
)

type bundleVectors struct {
	Format    string `json:"format"`
	Constants struct {
		BundleFormat string `json:"bundle_format"`
		MediaType    string `json:"media_type"`
		MaxEvents    int    `json:"max_events"`
	} `json:"constants"`
	LogKey struct {
		Name string `json:"name"`
		X509 string `json:"public_x509_b64"`
	} `json:"log_key"`
	Cases []struct {
		Name       string    `json:"name"`
		Pages      []string  `json:"pages"`
		HeadHex    *[]string `json:"head_strings_hex"`
		NowMs      int64     `json:"now_ms"`
		HeadSeenMs int64     `json:"head_seen_ms"`
		WindowMs   int64     `json:"window_ms"`
		UseLogKey  bool      `json:"use_log_key"`
		Subject    struct {
			Address string `json:"address"`
			FQDN    string `json:"fqdn"`
		} `json:"subject"`
		Expect struct {
			Valid             bool     `json:"valid"`
			Failure           *string  `json:"failure"`
			Head              *string  `json:"head"`
			WalkFailure       *string  `json:"walk_failure"`
			Proofs            []string `json:"proofs"`
			KeyAuthorised     bool     `json:"key_authorised"`
			FullyProven       bool     `json:"fully_proven"`
			CheckpointsSigned bool     `json:"checkpoints_signed"`
			Breaks            []string `json:"breaks"`
		} `json:"expect"`
	} `json:"cases"`
	Refusals []struct {
		Name   string `json:"name"`
		Bundle string `json:"bundle"`
	} `json:"refusals"`
}

func str(p *string) string {
	if p == nil {
		return "<null>"
	}
	return *p
}

func TestBundleVectorsHoldAgainstThisVerifier(t *testing.T) {
	var v bundleVectors
	readVectors(t, "kel-bundle-vectors.json", &v)
	if v.Format != "whisper-kel-bundle-vectors/1" || v.Constants.BundleFormat != BundleFormat ||
		v.Constants.MediaType != BundleMediaType || v.Constants.MaxEvents != MaxPageEvents {
		t.Fatalf("the bundle vectors' constants are not this package's: %+v", v.Constants)
	}
	key, err := LogKeyFromSPKI(v.LogKey.Name, unb64(t, v.LogKey.X509))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, c := range v.Cases {
		var pages []*Page
		for _, raw := range c.Pages {
			p, err := ParsePage(raw)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			if PageJSON(p) != raw {
				t.Fatalf("%s: the page does not write back to the service's canonical form", c.Name)
			}
			pages = append(pages, p)
		}
		var head *Head
		if c.HeadHex != nil {
			var strs [][]byte
			for _, h := range *c.HeadHex {
				strs = append(strs, unhex(t, h))
			}
			if head, err = ParseHead(strs); err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
		}
		o := VerifyOptions{Head: head, NowMillis: c.NowMs, HeadSeenMillis: c.HeadSeenMs, LagWindowMillis: c.WindowMs}
		if c.UseLogKey {
			o.LogKey = key
		}
		r := VerifyBundle(pages, Subject{Address: c.Subject.Address, FQDN: c.Subject.FQDN}, o)
		w := c.Expect
		if r.Valid != w.Valid {
			t.Fatalf("%s: valid %v (%s %s), want %v", c.Name, r.Valid, r.Failure, r.Reason, w.Valid)
		}
		if got := string(r.Failure); (w.Failure == nil && got != "") || (w.Failure != nil && got != *w.Failure) {
			t.Fatalf("%s: failure %q (%s), want %s", c.Name, got, r.Reason, str(w.Failure))
		}
		if got := string(r.Head); (w.Head == nil && got != "") || (w.Head != nil && got != *w.Head) {
			t.Fatalf("%s: head %q, want %s", c.Name, got, str(w.Head))
		}
		walk := ""
		if r.Walk != nil {
			walk = string(r.Walk.Failure)
		}
		if (w.WalkFailure == nil && walk != "") || (w.WalkFailure != nil && walk != *w.WalkFailure) {
			t.Fatalf("%s: walk %q, want %s", c.Name, walk, str(w.WalkFailure))
		}
		var proofs []string
		for _, p := range r.Proofs {
			proofs = append(proofs, string(p.State))
		}
		if strings.Join(proofs, ",") != strings.Join(w.Proofs, ",") {
			t.Fatalf("%s: proofs %v, want %v", c.Name, proofs, w.Proofs)
		}
		if r.KeyAuthorised() != w.KeyAuthorised || r.FullyProven() != w.FullyProven ||
			r.CheckpointsSigned != w.CheckpointsSigned {
			t.Fatalf("%s: authorised %v proven %v signed %v", c.Name, r.KeyAuthorised(), r.FullyProven(), r.CheckpointsSigned)
		}
		var breaks []string
		for _, b := range r.Breaks() {
			breaks = append(breaks, strconv.FormatInt(b.Sequence, 10)+":"+b.What)
		}
		if strings.Join(breaks, ",") != strings.Join(w.Breaks, ",") {
			t.Fatalf("%s: breaks %v, want %v", c.Name, breaks, w.Breaks)
		}
		checked++
	}
	for _, f := range v.Refusals {
		if _, err := ParsePage(f.Bundle); err == nil {
			t.Fatalf("%s: a refused bundle was read", f.Name)
		}
		checked++
	}
	if checked < 44 {
		t.Fatalf("only %d bundle vectors checked", checked)
	}
}

func TestAnyOfSeveralLogKeysSignsACheckpoint(t *testing.T) {
	var v bundleVectors
	readVectors(t, "kel-bundle-vectors.json", &v)
	key, _ := LogKeyFromSPKI(v.LogKey.Name, unb64(t, v.LogKey.X509))
	other, _ := NewLogKey(v.LogKey.Name, make([]byte, 32))
	c := v.Cases[0]
	var pages []*Page
	for _, raw := range c.Pages {
		p, _ := ParsePage(raw)
		pages = append(pages, p)
	}
	sub := Subject{Address: c.Subject.Address, FQDN: c.Subject.FQDN}
	var strs [][]byte
	for _, h := range *c.HeadHex {
		strs = append(strs, unhex(t, h))
	}
	head, _ := ParseHead(strs)
	o := VerifyOptions{Head: head, NowMillis: c.NowMs, HeadSeenMillis: c.HeadSeenMs, LagWindowMillis: c.WindowMs,
		LogKeys: []*LogKey{other, key}}
	if r := VerifyBundle(pages, sub, o); !r.Valid || !r.CheckpointsSigned {
		t.Fatalf("a checkpoint signed by the second key verifies: %s %s", r.Failure, r.Reason)
	}
	o.LogKeys = []*LogKey{other}
	if r := VerifyBundle(pages, sub, o); r.Failure != BundleCheckpointUnverified {
		t.Fatalf("no key of the log signed it: %s", r.Failure)
	}
}
