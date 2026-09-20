// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/sendbeam/engine/discovery"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
)

// runLocalOnlySend performs a genuinely offline send: the peer is a trusted
// paired device, the route is a validated local endpoint (manual --peer-addr
// or a discovered candidate), and the transfer runs through
// packages/engine/localtransfer — no public signaling server, STUN/TURN,
// relay, or updater is contacted at any step (V21-PR06).
func runLocalOnlySend(env *CLIEnvironment, filePaths []string, hp handoffPayload, toDevice, peerAddr string, requirePadding, privateMode, jsonOutput bool, stdout, stderr io.Writer) int {
	// Policy gate (defense in depth): the dispatcher only routes here when
	// the effective policy is local-only, but verify again — a local-only
	// send must never silently become an online send.
	policy, perr := resolveNetworkPolicy("", env.ConfigDir)
	if perr != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %v\n", perr)
		return 2
	}
	if policy != netpolicy.LocalOnly {
		_, _ = fmt.Fprintln(stderr, "sendbeam send: local-only send requires --network-policy=local-only (refusing to fall back to online)")
		return 2
	}
	if hp.Kind != "" {
		_, _ = fmt.Fprintln(stderr, "sendbeam send: --text/--link handoffs are not supported over --network-policy=local-only in this release (files only)")
		return 2
	}
	if len(filePaths) == 0 {
		_, _ = fmt.Fprintln(stderr, "sendbeam send: a file to send is required")
		return 2
	}
	if toDevice == "" {
		_, _ = fmt.Fprintln(stderr, "sendbeam send: --network-policy=local-only requires --to <trusted device> (no invite codes offline)")
		return 2
	}
	if peerAddr == "" {
		_, _ = fmt.Fprintln(stderr, "sendbeam send: --network-policy=local-only requires --peer-addr <ip:port> (run `sendbeam pair-local start` on the receiver to get its listen address)")
		return 2
	}

	ctx := context.Background()

	// Trust gate: resolveSendTargets rejects unknown or revoked devices and
	// resolves the pair secret. Unknown devices fail closed here.
	resolved, err := resolveSendTargets(ctx, env, []string{toDevice})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %v\n", err)
		return 1
	}
	rec := resolved[0]

	identity, err := env.IdentityMgr.GetOrCreateIdentity()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: identity: %v\n", err)
		return 1
	}

	// Route gate: the endpoint is validated against the interface-derived
	// route policy. Non-local addresses (e.g. a public IP) are rejected.
	tab := discovery.NewCandidateTable(discovery.RoutePolicy{AllowLoopback: true}, 16, 5*time.Minute)
	endpoint, err := tab.AddManual(rec.record.DeviceID, peerAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: --peer-addr %q rejected: %v\n", peerAddr, err)
		return 2
	}

	sources, _, err := transfer.NewOSFileSources(filePaths)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %v\n", err)
		return 1
	}

	var transport string
	var sentBytes int64
	out, err := localtransfer.Transfer(ctx, localtransfer.Options{
		Identity:       identity,
		Store:          env.TrustStore,
		Resolver:       env.Secrets,
		Table:          tab,
		PeerDeviceID:   rec.record.DeviceID,
		PeerLabel:      rec.record.LocalLabel,
		Role:           rendezvous.RoleOfferer,
		Sources:        sources,
		RequirePadding: requirePadding,
		Private:        privateMode,
		OnTransport: func(t string) {
			transport = t
			if !jsonOutput {
				_, _ = fmt.Fprintf(stdout, "route: %s (local direct, %s)\n", t, endpoint.Endpoint.HostPort)
			}
		},
		OnProgress: func(n int64) {
			sentBytes = n
			if !jsonOutput {
				_, _ = fmt.Fprintf(stderr, "\rprogress: %s", humanBytes(n))
			}
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "\nsendbeam send: local-only transfer failed: %v\n", err)
		return 1
	}

	if jsonOutput {
		result := map[string]any{
			"status":         "sent",
			"network_policy": "local-only",
			"device_id":      rec.record.DeviceID,
			"peer_addr":      endpoint.Endpoint.HostPort,
			"transport":      transport,
			"bytes":          sentBytes,
			"name":           out.Name,
			"size":           out.Size,
			"digest":         out.Digest,
		}
		raw, _ := json.Marshal(result)
		_, _ = fmt.Fprintln(stdout, string(raw))
		return 0
	}
	_, _ = fmt.Fprintf(stderr, "\n")
	_, _ = fmt.Fprintf(stdout, "network policy: local-only (no public signaling, STUN/TURN, or relay contacted)\n")
	_, _ = fmt.Fprintf(stdout, "sent %s to %s (%s)\n", humanBytes(out.Size), rec.record.LocalLabel, rec.record.DeviceID)
	return 0
}
