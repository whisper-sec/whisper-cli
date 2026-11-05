// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)

package enforce

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// token_windows.go makes the token an enforced agent runs under: the
// invoking user, in a logon session of its own (so a fresh logon SID that nothing else on the
// machine carries, which is what the filters key on), with administrator rights removed.

var (
	advapi32                  = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW            = advapi32.NewProc("LogonUserW")
	procCreateRestrictedToken = advapi32.NewProc("CreateRestrictedToken")
	secur32                   = windows.NewLazySystemDLL("secur32.dll")
	procLsaGetLogonSessionDat = secur32.NewProc("LsaGetLogonSessionData")
	procLsaFreeReturnBuffer   = secur32.NewProc("LsaFreeReturnBuffer")
)

const (
	logon32LogonNewCredentials = 9
	logon32ProviderWinNT50     = 3
	disableMaxPrivilege        = 0x1
	seGroupLogonID             = 0xC0000000
	seGroupIntegrity           = 0x20
	tokenDefaultDaclClass      = 6
	tokenStatisticsClass       = 10
)

// agentToken is the agent's primary token and the logon SID it alone carries.
type agentToken struct {
	tok      windows.Token
	logonSID string
	userSID  string
}

func (a *agentToken) close() {
	if a != nil && a.tok != 0 {
		a.tok.Close()
		a.tok = 0
	}
}

// newAgentToken builds the token. The caller must be elevated: the restricted token is derived
// from the caller's own credentials, never from a password.
func newAgentToken() (_ *agentToken, err error) {
	self := windows.GetCurrentProcessToken()
	tu, err := self.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("reading this process's user: %w", err)
	}
	user := tu.User.Sid
	account, domain, _, err := user.LookupAccount("")
	if err != nil {
		return nil, fmt.Errorf("naming this process's user: %w", err)
	}
	// A NEW_CREDENTIALS logon checks no password and needs no privilege: it clones the caller's
	// token into a new logon session. The empty password is only used for outbound network
	// authentication, which the agent's filters refuse anyway.
	acc, _ := windows.UTF16PtrFromString(account)
	dom, _ := windows.UTF16PtrFromString(domain)
	empty, _ := windows.UTF16PtrFromString("")
	var logon windows.Token
	if r, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(acc)), uintptr(unsafe.Pointer(dom)),
		uintptr(unsafe.Pointer(empty)), logon32LogonNewCredentials, logon32ProviderWinNT50,
		uintptr(unsafe.Pointer(&logon))); r == 0 {
		return nil, fmt.Errorf("starting a logon session for the agent: %w", e)
	}
	defer logon.Close()

	logonSID, err := tokenLogonSID(logon)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	localAdmin, err := windows.StringToSid("S-1-5-114") // local account and member of Administrators
	if err != nil {
		return nil, err
	}
	deny := []windows.SIDAndAttributes{{Sid: admins}, {Sid: localAdmin}}
	var restricted windows.Token
	if r, _, e := procCreateRestrictedToken.Call(uintptr(logon), disableMaxPrivilege, uintptr(len(deny)),
		uintptr(unsafe.Pointer(&deny[0])), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted))); r == 0 {
		return nil, fmt.Errorf("removing administrator rights from the agent's token: %w", e)
	}
	defer func() {
		if err != nil {
			restricted.Close()
		}
	}()

	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		return nil, err
	}
	tml := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: seGroupIntegrity}}
	if err := windows.SetTokenInformation(restricted, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&tml)), tml.Size()); err != nil {
		return nil, fmt.Errorf("lowering the agent's token to medium integrity: %w", err)
	}

	// An elevated token's default DACL names only Administrators and SYSTEM, so a de-elevated
	// process could not open its own objects and dies in DLL initialisation (measured:
	// 0xC0000142). Grant the user, this logon session and SYSTEM, on new objects and on the token.
	sd, err := windows.SecurityDescriptorFromString(
		"D:(A;;GA;;;" + user.String() + ")(A;;GA;;;" + logonSID + ")(A;;GA;;;SY)")
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	dd := struct{ acl *windows.ACL }{dacl}
	if err := windows.SetTokenInformation(restricted, tokenDefaultDaclClass,
		(*byte)(unsafe.Pointer(&dd)), uint32(unsafe.Sizeof(dd))); err != nil {
		return nil, fmt.Errorf("setting the agent token's default DACL: %w", err)
	}
	if err := windows.SetSecurityInfo(windows.Handle(restricted), windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return nil, fmt.Errorf("setting the agent token's own DACL: %w", err)
	}
	return &agentToken{tok: restricted, logonSID: logonSID, userSID: user.String()}, nil
}

// tokenLogonSID is the SID of the token's logon session (the group marked SE_GROUP_LOGON_ID).
func tokenLogonSID(t windows.Token) (string, error) {
	groups, err := t.GetTokenGroups()
	if err != nil {
		return "", fmt.Errorf("reading the agent token's groups: %w", err)
	}
	for _, g := range groups.AllGroups() {
		if g.Attributes&seGroupLogonID == seGroupLogonID {
			return g.Sid.String(), nil
		}
	}
	return "", errors.New("the agent's token carries no logon SID, so no filter could tell it apart")
}

// Elevated reports whether this process runs with administrator rights, which adding filters
// to the engine and creating the agent's token both need.
func Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// InsideEnforced is true in a process an enforced run started: its logon session is a
// NewCredentials one and it is not elevated. Even then `whisper ip` trusts only the echo's
// observation, so a process that only looks enforced cannot make a wrong source pass.
func InsideEnforced() bool {
	t := windows.GetCurrentProcessToken()
	if t.IsElevated() {
		return false
	}
	lt, err := logonType(t)
	return err == nil && lt == logon32LogonNewCredentials
}

// logonType reads the type of the token's logon session from the LSA.
func logonType(t windows.Token) (uint32, error) {
	var stats tokenStatistics
	var n uint32
	if err := windows.GetTokenInformation(t, tokenStatisticsClass, (*byte)(unsafe.Pointer(&stats)),
		uint32(unsafe.Sizeof(stats)), &n); err != nil {
		return 0, err
	}
	luid := stats.AuthenticationID
	var data *byte
	if r, _, _ := procLsaGetLogonSessionDat.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&data))); r != 0 || data == nil {
		return 0, fmt.Errorf("LsaGetLogonSessionData: 0x%08X", r)
	}
	defer procLsaFreeReturnBuffer.Call(uintptr(unsafe.Pointer(data))) //nolint:errcheck
	// SECURITY_LOGON_SESSION_DATA.LogonType is at offset 64 on 64-bit Windows (measured).
	return *(*uint32)(unsafe.Add(unsafe.Pointer(data), 64)), nil
}

// tokenStatistics is TOKEN_STATISTICS (56 bytes, AuthenticationId at 8, measured). It is a
// struct rather than a byte array so the buffer has the alignment the call requires.
type tokenStatistics struct {
	TokenID            windows.LUID
	AuthenticationID   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedID         windows.LUID
}
