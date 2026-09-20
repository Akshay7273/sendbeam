// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/sendbeam/engine/localrendezvous"
	"github.com/sendbeam/engine/localtransfer"
	"github.com/sendbeam/wire"
)

// runLocalOnlyReceive starts a local rendezvous listener and accepts the
// next transfer from a paired device — no invite code, no public signaling
// server, STUN/TURN, or relay at any step (V21-PR06).
//
// Only paired, non-revoked devices are admitted: the rendezvous server
// refuses unknown dialers at the door, and the Opaque ceremony authenticates
// the claimed device ID before any bytes move.
func runLocalOnlyReceive(env *CLIEnvironment, outDir, bindAddr string, requirePadding, privateMode bool, stdout, stderr io.Writer) int {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam receive: %v\n", err)
		return 1
	}

	// Bind a real LAN address so the sender can reach us. Loopback-only is
	// rejected here: an invitation carrying 127.0.0.1 is unusable
	// cross-device, and silently listening on loopback would lie about it.
	bind := bindAddr
	if bind == "" {
		lan, err := localrendezvous.LANBindAddr()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam receive: cannot find a LAN interface: %v\n", err)
			return 1
		}
		bind = lan
	}

	identity, err := env.IdentityMgr.GetOrCreateIdentity()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam receive: identity: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := localrendezvous.NewServer(localrendezvous.Config{
		BindAddr:      bind,
		AllowWildcard: false,
	}, env.TrustStore)
	addr, err := srv.Start(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam receive: listen on %s: %v\n", bind, err)
		return 1
	}
	defer srv.Close()

	s := newStyleFromWriter(stderr)
	_, _ = fmt.Fprintf(stdout, "network policy: local-only (no public signaling, STUN/TURN, or relay contacted)\n")
	_, _ = fmt.Fprintf(stdout, "listening on %s — give this address to the sender as --peer-addr\n", addr)
	_, _ = fmt.Fprintln(stderr, s.dim("Waiting for a paired device … (Ctrl-C to stop)"))

	progress := newProgress(0)
	out, err := localtransfer.Receive(ctx, localtransfer.ReceiveOptions{
		Identity:       identity,
		Store:          env.TrustStore,
		Resolver:       env.Secrets,
		Server:         srv,
		DestDir:        outDir,
		RequirePadding: requirePadding,
		Private:        privateMode,
		OnTransport: func(t string) {
			_, _ = fmt.Fprintf(stdout, "route: %s (local direct)\n", t)
		},
		OnProgress: func(n int64) {
			progress.report(n)
		},
		OnManifest: func(entry wire.FileEntry) {
			progress.setTotal(entry.Size)
			progress.setFiles([]progressFile{{name: entry.Name, size: entry.Size}})
			_, _ = fmt.Fprintf(stderr, "receiving %s …\n", entry.Name)
		},
	})
	progress.finish()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
		return 1
	}
	_, _ = fmt.Fprintln(stdout)
	if len(out.Files) == 1 {
		_, _ = fmt.Fprintln(stdout, s.check("Received "+s.bold(out.Name)+" ("+humanBytes(out.Size)+") → "+out.Path+"."))
	} else {
		_, _ = fmt.Fprintln(stdout, s.check("Received "+s.bold(fmt.Sprintf("%d files", len(out.Files)))+" ("+humanBytes(out.Size)+") → "+outDir+"."))
	}
	_, _ = fmt.Fprintf(stdout, "  %s  %s\n", s.grey("Fingerprint:"), fingerprint(out.Handshake.Master))
	if len(out.Files) == 1 {
		_, _ = fmt.Fprintf(stdout, "  %s  %s\n", s.grey("SHA-256:"), out.Digest)
	}
	return 0
}
