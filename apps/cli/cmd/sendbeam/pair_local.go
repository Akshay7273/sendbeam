// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sendbeam/engine/localpairing"
	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

type pairLocalInviteJSON struct {
	Status      string `json:"status"`
	Invitation  string `json:"invitation"`
	Address     string `json:"address"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expires_at"`
}

type pairLocalJoinJSON struct {
	Status   string `json:"status"`
	DeviceID string `json:"device_id"`
}

func runPairLocal(args []string) int {
	return executePairLocal(args, os.Stdout, os.Stderr)
}

func executePairLocal(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "sendbeam pair-local: invite or join required")
		_, _ = fmt.Fprintln(stderr, "  sendbeam pair-local invite [--window 60s] [--bind ip:port] [--json]")
		_, _ = fmt.Fprintln(stderr, "  sendbeam pair-local join [--json] < invitation.txt")
		_, _ = fmt.Fprintln(stderr, "The invitation contains the pairing secret: pipe it via stdin, never pass it as a command argument.")
		return 2
	}
	switch args[0] {
	case "invite":
		return executePairLocalInvite(args[1:], stdout, stderr)
	case "join":
		return executePairLocalJoin(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "sendbeam pair-local: unknown subcommand %q (want invite or join)\n", args[0])
		return 2
	}
}

func executePairLocalInvite(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair-local invite", flag.ContinueOnError)
	fs.SetOutput(stderr)
	window := fs.Duration("window", time.Minute, "how long the pairing window stays open")
	bindAddr := fs.String("bind", "", "local listen address ip:port (default: first LAN interface, ephemeral port)")
	jsonOutput := fs.Bool("json", false, "output JSON format")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *window <= 0 || *window > 10*time.Minute {
		_, _ = fmt.Fprintln(stderr, "sendbeam pair-local invite: --window must be between 1s and 10m")
		return 2
	}
	// V21-PR06: bind a real LAN address. A loopback-only listener would hand
	// the joiner an invitation it cannot reach from another device.
	bind := *bindAddr
	if bind == "" {
		lan, err := localrendezvous.LANBindAddr()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam pair-local invite: no LAN interface: %v\n", err)
			return 1
		}
		bind = lan
	}
	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := localrendezvous.NewServer(localrendezvous.Config{BindAddr: bind, AllowWildcard: false}, env.TrustStore)
	addr, err := srv.Start(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: start local rendezvous: %v\n", err)
		return 1
	}
	defer func() { _ = srv.Close() }()
	id, err := env.IdentityMgr.GetOrCreateIdentity()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fingerprint := wire.DeriveDeviceID(id.PublicKey)
	in, err := localpairing.CreateInvitation(srv, addr.String(), fingerprint, *window)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	masterKey, err := in.MasterKey()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		out, _ := json.Marshal(pairLocalInviteJSON{
			Status: "invitation-created", Invitation: in.Encode(),
			Address: in.Address, Fingerprint: in.Fingerprint,
			ExpiresAt: in.ExpiresAt.Format(time.RFC3339),
		})
		_, _ = fmt.Fprintln(stdout, string(out))
	} else {
		_, _ = fmt.Fprintln(stdout, "Share this invitation with the joining device (valid until "+in.ExpiresAt.Format("15:04:05")+").")
		_, _ = fmt.Fprintln(stdout, "The invitation contains the pairing secret; share it as a QR code, not in logs or chat history.")
		_, _ = fmt.Fprintln(stdout, "")
		_, _ = fmt.Fprintln(stdout, "  "+in.Encode())
		_, _ = fmt.Fprintln(stdout, "")
		_, _ = fmt.Fprintln(stdout, "Waiting for the joiner to pair... (Ctrl+C to cancel)")
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "CLI Device"
	}
	coordinator := trust.NewPairingCoordinator(env.IdentityMgr, env.TrustStore)
	res, err := localpairing.Accept(ctx, srv, localpairing.Options{
		Coordinator: coordinator, DeviceName: hostname, MasterKey: masterKey,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: pairing failed: %v\n", err)
		return 1
	}
	if *jsonOutput {
		out, _ := json.Marshal(pairLocalJoinJSON{Status: "paired", DeviceID: res.PeerRecord.DeviceID})
		_, _ = fmt.Fprintln(stdout, string(out))
	} else {
		_, _ = fmt.Fprintf(stdout, "Paired with device %s\n", res.PeerRecord.DeviceID)
	}
	return 0
}

func executePairLocalJoin(args []string, stdout, stderr io.Writer) int {
	return executePairLocalJoinStdin(args, os.Stdin, stdout, stderr)
}

// executePairLocalJoinStdin is the testable core of the join flow; stdin is
// injected so tests never need a real pipe.
func executePairLocalJoinStdin(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair-local join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "output JSON format")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// V21-PR06: the invitation carries the pairing secret. It is never
	// accepted as a command argument (argv is visible to other processes);
	// read it from stdin instead.
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "sendbeam pair-local join: do not pass the invitation as an argument; pipe it via stdin")
		return 2
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, 64*1024))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: reading invitation from stdin: %v\n", err)
		return 1
	}
	invitation := strings.TrimSpace(string(raw))
	if invitation == "" {
		_, _ = fmt.Fprintln(stderr, "sendbeam pair-local join: no invitation on stdin")
		return 2
	}
	in, err := localpairing.ParseInvitation(invitation)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid invitation: %v\n", err)
		return 2
	}
	masterKey, err := in.MasterKey()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid invitation: %v\n", err)
		return 2
	}
	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "CLI Device"
	}
	coordinator := trust.NewPairingCoordinator(env.IdentityMgr, env.TrustStore)
	res, err := localpairing.Join(ctx, in, localpairing.Options{
		Coordinator: coordinator, DeviceName: hostname, MasterKey: masterKey,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: pairing failed: %v\n", err)
		return 1
	}
	if *jsonOutput {
		out, _ := json.Marshal(pairLocalJoinJSON{Status: "paired", DeviceID: res.PeerRecord.DeviceID})
		_, _ = fmt.Fprintln(stdout, string(out))
	} else {
		_, _ = fmt.Fprintf(stdout, "Paired with device %s\n", res.PeerRecord.DeviceID)
		_, _ = fmt.Fprintf(stdout, "Verify the fingerprint matches what the inviter sees: %s\n", in.Fingerprint)
	}
	return 0
}
