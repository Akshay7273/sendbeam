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
		fmt.Fprintln(stderr, "sendbeam pair-local: invite or join required")
		fmt.Fprintln(stderr, "  sendbeam pair-local invite [--window 60s] [--json]")
		fmt.Fprintln(stderr, "  sendbeam pair-local join <invitation> [--json]")
		return 2
	}
	switch args[0] {
	case "invite":
		return executePairLocalInvite(args[1:], stdout, stderr)
	case "join":
		return executePairLocalJoin(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "sendbeam pair-local: unknown subcommand %q (want invite or join)\n", args[0])
		return 2
	}
}

func executePairLocalInvite(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair-local invite", flag.ContinueOnError)
	fs.SetOutput(stderr)
	window := fs.Duration("window", time.Minute, "how long the pairing window stays open")
	jsonOutput := fs.Bool("json", false, "output JSON format")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *window <= 0 || *window > 10*time.Minute {
		fmt.Fprintln(stderr, "sendbeam pair-local invite: --window must be between 1s and 10m")
		return 2
	}
	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := localrendezvous.NewServer(localrendezvous.Config{BindAddr: "127.0.0.1:0"}, env.TrustStore)
	addr, err := srv.Start(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "error: start local rendezvous: %v\n", err)
		return 1
	}
	defer srv.Close()
	id, err := env.IdentityMgr.GetOrCreateIdentity()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	fingerprint := wire.DeriveDeviceID(id.PublicKey)
	in, err := localpairing.CreateInvitation(srv, addr.String(), fingerprint, *window)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	masterKey, err := in.MasterKey()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		out, _ := json.Marshal(pairLocalInviteJSON{
			Status: "invitation-created", Invitation: in.Encode(),
			Address: in.Address, Fingerprint: in.Fingerprint,
			ExpiresAt: in.ExpiresAt.Format(time.RFC3339),
		})
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprintln(stdout, "Share this invitation with the joining device (valid until "+in.ExpiresAt.Format("15:04:05")+").")
		fmt.Fprintln(stdout, "The invitation contains the pairing secret; share it as a QR code, not in logs or chat history.")
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "  "+in.Encode())
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Waiting for the joiner to pair... (Ctrl+C to cancel)")
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
		fmt.Fprintf(stderr, "error: pairing failed: %v\n", err)
		return 1
	}
	if *jsonOutput {
		out, _ := json.Marshal(pairLocalJoinJSON{Status: "paired", DeviceID: res.PeerRecord.DeviceID})
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprintf(stdout, "Paired with device %s\n", res.PeerRecord.DeviceID)
	}
	return 0
}

func executePairLocalJoin(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pair-local join", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "output JSON format")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "sendbeam pair-local join: an invitation string is required")
		return 2
	}
	in, err := localpairing.ParseInvitation(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid invitation: %v\n", err)
		return 2
	}
	masterKey, err := in.MasterKey()
	if err != nil {
		fmt.Fprintf(stderr, "error: invalid invitation: %v\n", err)
		return 2
	}
	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
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
		fmt.Fprintf(stderr, "error: pairing failed: %v\n", err)
		return 1
	}
	if *jsonOutput {
		out, _ := json.Marshal(pairLocalJoinJSON{Status: "paired", DeviceID: res.PeerRecord.DeviceID})
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprintf(stdout, "Paired with device %s\n", res.PeerRecord.DeviceID)
		fmt.Fprintf(stdout, "Verify the fingerprint matches what the inviter sees: %s\n", in.Fingerprint)
	}
	return 0
}
