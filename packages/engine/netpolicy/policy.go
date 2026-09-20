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

import (
	"errors"
	"strings"
)

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

// Parse converts a user-supplied policy name to a Policy.
func Parse(s string) (Policy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "online", "automatic":
		return Online, nil
	case "prefer-local", "prefer_local":
		return PreferLocal, nil
	case "local-only", "local_only", "local":
		return LocalOnly, nil
	default:
		return Online, errors.New("netpolicy: unknown policy (want online, prefer-local, or local-only)")
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
