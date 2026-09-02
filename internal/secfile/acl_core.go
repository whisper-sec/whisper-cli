// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package secfile

// acl_core.go is the PURE half of the Windows read-back: the access-mask table
// and the per-ACE decision, carrying no syscall and no build tag, so the
// judgement is exercised by every lane rather than only by the one Windows
// runner. Only the walk that resolves a principal needs Windows.
//
// A second caller asks the same question about the same objects, so the table
// lives here rather than in two copies: one table, one decision, one place to
// change it.

// ACE types from winnt.h. Pinned to the SDK constants in secfile_windows.go, so
// a drift between this table and the header is a compile error on the Windows
// build rather than a silent mis-judgement everywhere.
const (
	aceTypeAllowed byte = 0 // ACCESS_ALLOWED_ACE_TYPE
	aceTypeDenied  byte = 1 // ACCESS_DENIED_ACE_TYPE
)

// ExposureMask is the set of access rights that count as "can read or alter"
// for a private file. An ALLOW ace granting any of these to a principal that is
// not the owner, SYSTEM or Administrators means the file is exposed.
//
// It deliberately covers the WRITE rights as well as the read ones. A principal
// holding WRITE_DAC or WRITE_OWNER can grant itself the read at any moment, so
// on a file whose risk is disclosure those two ARE disclosure, one call later.
const ExposureMask uint32 = 0x80000000 | // GENERIC_READ
	0x40000000 | // GENERIC_WRITE
	0x20000000 | // GENERIC_EXECUTE (FILE_EXECUTE implies FILE_READ_DATA on a data file)
	0x10000000 | // GENERIC_ALL
	0x00000001 | // FILE_READ_DATA / FILE_LIST_DIRECTORY
	0x00000002 | // FILE_WRITE_DATA / FILE_ADD_FILE
	0x00000004 | // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	0x00000008 | // FILE_READ_EA
	0x00000010 | // FILE_WRITE_EA
	0x00000100 | // FILE_WRITE_ATTRIBUTES
	0x00010000 | // DELETE
	0x00040000 | // WRITE_DAC
	0x00080000 //   WRITE_OWNER

// ACEJudgment is the verdict on one DACL ace, reached from the ace TYPE and
// MASK alone. Resolving the principal an ace names needs Windows; deciding
// whether the principal even matters does not, and that split is what keeps the
// table testable on every platform.
type ACEJudgment uint8

const (
	// ACEHarmless: this ace cannot widen access, whoever it names. A deny, or
	// an allow whose mask grants nothing this gate cares about.
	ACEHarmless ACEJudgment = iota
	// ACENeedsPrincipal: this ace grants exposing rights, so the verdict now
	// turns on WHO it names, which only the Windows binding can answer.
	ACENeedsPrincipal
	// ACEUnjudgeable: an ace shape this walk cannot parse. Terminal, and it
	// fails toward "exposed" on purpose.
	ACEUnjudgeable
)

// JudgeACE is the decision table behind the DACL read-back. Its three fail
// directions each have a reason:
//
//   - a DENY ace can only ever tighten access, so it is harmless to trust;
//   - a plain ALLOW ace is judged by its mask and then by the principal it
//     names, which only the Windows binding can resolve;
//   - any OTHER ace type, a callback (conditional) allow, an object allow, or
//     whatever winnt.h grows next, can still GRANT read while keeping its SID
//     at a type-specific offset this walk does not know. It is unjudgeable and
//     the gate fails toward "exposed". Without that last row a single
//     conditional-allow ace would slip a grant-Everyone-read DACL past as
//     private.
func JudgeACE(aceType byte, mask uint32) ACEJudgment {
	switch aceType {
	case aceTypeDenied:
		return ACEHarmless
	case aceTypeAllowed:
		if mask&ExposureMask == 0 {
			return ACEHarmless
		}
		return ACENeedsPrincipal
	default:
		return ACEUnjudgeable
	}
}
