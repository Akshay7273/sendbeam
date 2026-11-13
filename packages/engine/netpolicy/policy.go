// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

// Package netpolicy defines the user-selected network policy for SendBeam
// v2.1 "Nearby & Offline" (ADR 0011, V21-PR06).
//
// The policy controls which network paths the engine may use:
//
//   - LocalOnly: only policy-approved local paths. No public signaling,
//     no external ICE services, no relay. Transfers fail closed if no
//     local route exists; there is no silent online fallback.
//   - PreferLocal: try local paths first, fall back to approved online
//     paths (signaling server, STUN, relay) if local fails.
//   - Online: the v2.0 behavior; local paths may be used opportunistically
//     but online services are always available.
//
// The policy is separate from traffic padding: a local route never
// justifies disabling authentication, encryption, or integrity.
package netpolicy

import "strings"

// Policy is a network path selection policy.
type Policy int

const (
	// Online is the default v2.0 behavior.
	Online Policy = iota
	// PreferLocal tries local paths first, then online.
	PreferLocal
	// LocalOnly uses only local paths; fails closed without one.
	LocalOnly
)

// String returns the canonical policy name.
func (p Policy) String() string {
	switch p {
	case LocalOnly:
		return "local-only"
	case PreferLocal:
		return "prefer-local"
	default:
		return "online"
	}
}

// PolicyParseError reports that a stored policy name is not one of the
// values Parse accepts. Callers that cannot ask the user at the failure
// point (runtime policy retrieval) treat it as LocalOnly — the
// least-permissive policy — rather than falling back to Online.
type PolicyParseError struct {
	// Input is the unparseable policy name as it was stored.
	Input string
}

func (e *PolicyParseError) Error() string {
	in := "'" + sInput(e.Input) + "'"
	if e.Input == "" {
		in = "(empty)"
	}
	return "netpolicy: unknown policy " + in + " (want online, prefer-local, or local-only)"
}

func sInput(s string) string { return s }

// Parse converts a user-supplied policy name to a Policy.
//
// The zero Policy is Online, but on error Parse returns LocalOnly together
// with a *PolicyParseError so that callers which ignore the error fail
// closed: an unrecognized stored policy must never silently broaden to the
// most permissive behavior (SB-R05).
func Parse(s string) (Policy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "online", "automatic":
		return Online, nil
	case "prefer-local", "prefer_local":
		return PreferLocal, nil
	case "local-only", "local_only", "local":
		return LocalOnly, nil
	default:
		return LocalOnly, &PolicyParseError{Input: s}
	}
}

// AllowsOnline reports whether the policy permits public services
// (signaling server, STUN, relay).
func (p Policy) AllowsOnline() bool {
	return p != LocalOnly
}

// RequiresLocal reports whether the policy mandates a local route.
func (p Policy) RequiresLocal() bool {
	return p == LocalOnly
}

// DispatchableUnder reports whether a job bound to policy p may be
// dispatched by a dispatcher running under the effective policy. This is
// the V21-PR07 attempt-binding rule: a job is dispatched only when its
// bound policy can be satisfied, never by silently broadening it.
//
//   - LocalOnly jobs dispatch only when the effective policy leaves a
//     local route available (LocalOnly or PreferLocal). The dispatcher
//     must still suppress any online fallback for them.
//   - Online jobs (including pre-V21-PR07 jobs, whose bound policy is
//     empty) dispatch only when the effective policy permits an online
//     route (Online or PreferLocal).
//   - PreferLocal jobs dispatch under any effective policy; the route is
//     chosen at send time within what the effective policy allows.
//
// A false result means the job is held: the dispatcher skips it with a
// clear reason and leaves its attempts untouched.
func (p Policy) DispatchableUnder(effective Policy) bool {
	switch p {
	case LocalOnly:
		return effective == LocalOnly || effective == PreferLocal
	case PreferLocal:
		return true
	default: // Online and any unrecognized value fail closed toward online semantics
		return effective == Online || effective == PreferLocal
	}
}

// ResolveEffective resolves the effective runtime network policy for an
// engine component from a lookup callback, failing closed (SB-R05):
//
//   - A healthy lookup is authoritative: its value is returned verbatim
//     and read exactly once.
//   - A nil lookup (component constructed without wiring) selects
//     LocalOnly — the least-permissive policy — and surfaces a notice.
//     It must never assume the most permissive behavior by default.
//   - A lookup that panics (a crashing config backend is indistinguishable
//     from an unreadable one at this layer) is recovered and selects
//     LocalOnly, with the reason surfaced through reporter. A nil reporter
//     suppresses only the message, never the fail-closed selection.
//
// Selection rationale: LocalOnly preserves every local recovery path
// (LAN discovery, the offline listener, local pairing) while denying the
// public network (signaling, STUN/TURN, relay, update checks). It is the
// only policy that is safe under uncertainty; Online is only correct when
// the user chose it or first-launch defaults apply (the caller distinguishes
// a MISSING config file — which Store.Load reports as defaults, not an
// error — from an UNUSABLE one).
func ResolveEffective(lookup func() Policy, reporter func(msg string)) Policy {
	if lookup == nil {
		if reporter != nil {
			reporter("policy lookup unavailable; failing closed to local-only")
		}
		return LocalOnly
	}
	var p Policy
	func() {
		defer func() {
			if r := recover(); r != nil {
				p = LocalOnly
				if reporter != nil {
					reporter("policy lookup failed (" + fmtPanic(r) + "); failing closed to local-only")
				}
			}
		}()
		p = lookup()
	}()
	return p
}

func fmtPanic(r any) string {
	if err, ok := r.(error); ok {
		return err.Error()
	}
	if s, ok := r.(string); ok {
		return s
	}
	return "non-error panic value"
}
