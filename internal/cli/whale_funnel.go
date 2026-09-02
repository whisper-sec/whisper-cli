// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package cli

// whale_funnel.go is `whisper whale funnel`.
//
// There is deliberately almost nothing in this file. Funnel is `serve` with one thing
// changed - who is answered - and the moment it became its own implementation the two
// would start to differ in a way nobody intended. So it is the same engine, built by
// newWhaleExposeCmd(whale.ScopeInternet) in whale_serve.go, and the scope is carried
// through as data rather than as a second code path.
//
// WHAT FUNNEL IS, AND IS NOT
//
// Theirs is a relay product: ports 443, 8443 and 10000 only, MagicDNS required, a
// certificate from a public CA, up to ten minutes of DNS propagation, and a rate-limit
// lockout of up to 34 hours if you thrash it. It has to be, because the node has no
// address the internet can reach.
//
// Ours is a publish verb. The /128 is globally routable and inbound-reachable already
// and the leaf is pinned by a TLSA in a signed zone. So a funnel does not deploy
// anything: it decides to answer strangers. That is the whole difference, and it is why
// the verb spends its care on CONSENT and on being switchable off rather than on plumbing:
//
// - it will not start without a typed `yes` or an explicit --yes;
// - it writes its record before it answers a single request, and refuses to serve at all
// if that record cannot be written, because an exposure nothing can find is an
// exposure nothing can stop;
// - `whisper whale status` shows it from any shell on the host, not only the one holding
// it, and says THE INTERNET rather than a checkmark;
// - `whisper whale funnel off` ends it in one word, from anywhere, and is idempotent.
