package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sendbeam/engine/receiver"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

func runListen(args []string) int {
	return executeListen(args, os.Stdout, os.Stderr)
}

func executeListen(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return executeListenWithContext(ctx, args, os.Stdin, stdout, stderr)
}

func executeListenWithContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dest := fs.String("dest", ".", "directory to write received files into")
	autoAccept := fs.Bool("auto-accept", false, "automatically accept transfers from trusted devices")
	once := fs.Bool("once", false, "exit after completing a single transfer")
	port := fs.Int("port", 53317, "local port for direct LAN peer discovery")
	server := fs.String("server", "", "signaling server URL")
	jsonOutput := fs.Bool("json", false, "output JSON format events")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	absDest, err := filepath.Abs(*dest)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: invalid destination directory: %v\n", err)
		return 2
	}
	_ = os.MkdirAll(absDest, 0700)

	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	localID, err := env.IdentityMgr.GetOrCreateIdentity()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error getting local identity: %v\n", err)
		return 1
	}

	tombstones := env.Tombstones

	serverURL := *server
	if serverURL == "" {
		serverURL = defaultServer
	}

	consentHandler := func(_ context.Context, req receiver.ConsentRequest) (receiver.ConsentDecision, error) {
		if *jsonOutput {
			evt := map[string]any{
				"event":          "consent_requested",
				"transfer_id":    req.TransferID,
				"peer_device_id": req.PeerDeviceID,
				"peer_label":     req.PeerLabel,
				"files":          req.Files,
				"total_size":     req.TotalSize,
				"dest_dir":       req.DestDir,
			}
			enc, _ := json.Marshal(evt)
			_, _ = fmt.Fprintln(stdout, string(enc))

			scanner := bufio.NewScanner(stdin)
			if scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "{") {
					var dec receiver.ConsentDecision
					if json.Unmarshal([]byte(line), &dec) == nil {
						return dec, nil
					}
				}
				if strings.EqualFold(line, "y") || strings.EqualFold(line, "yes") {
					return receiver.ConsentDecision{Accepted: true, DestDir: req.DestDir}, nil
				}
				return receiver.ConsentDecision{Accepted: false, Reason: "declined"}, nil
			}
			return receiver.ConsentDecision{Accepted: false, Reason: "no response on stdin"}, nil
		}

		s := newStyleFromWriter(stdout)
		_, _ = fmt.Fprintf(stdout, "\n%s from %s (%s):\n", s.bold("Incoming transfer"), s.bold(req.PeerLabel), req.PeerDeviceID)
		for _, f := range req.Files {
			_, _ = fmt.Fprintf(stdout, "  • %s (%s)\n", f.Name, humanBytes(f.Size))
		}
		_, _ = fmt.Fprintf(stdout, "Total: %d file(s), %s\n", len(req.Files), humanBytes(req.TotalSize))
		_, _ = fmt.Fprintf(stdout, "Accept transfer into %s? [y/N]: ", req.DestDir)

		scanner := bufio.NewScanner(stdin)
		if scanner.Scan() {
			ans := strings.TrimSpace(scanner.Text())
			if strings.EqualFold(ans, "y") || strings.EqualFold(ans, "yes") {
				return receiver.ConsentDecision{Accepted: true, DestDir: req.DestDir}, nil
			}
		}
		return receiver.ConsentDecision{Accepted: false, Reason: "declined by user"}, nil
	}

	listener, err := receiver.NewListener(receiver.Config{
		DestDir:        absDest,
		AutoAccept:     *autoAccept,
		Once:           *once,
		Port:           uint16(*port),
		Server:         serverURL,
		Identity:       localID,
		TrustStore:     env.TrustStore,
		Secrets:        env.Secrets,
		Tombstones:     tombstones,
		ConsentHandler: consentHandler,
		OnPeerDiscovered: func(peer receiver.DiscoveredPeer) {
			rec, err := env.TrustStore.GetDevice(ctx, peer.DeviceID)
			label := peer.DeviceID
			if err == nil && rec != nil {
				label = rec.LocalLabel
			}
			if *jsonOutput {
				_, _ = fmt.Fprintf(stdout, `{"event":"peer_discovered","device_id":%q,"label":%q,"ip":%q,"port":%d}`+"\n",
					peer.DeviceID, label, peer.IP.String(), peer.Port)
			} else {
				s := newStyleFromWriter(stdout)
				_, _ = fmt.Fprintf(stdout, "[%s] Discovered trusted peer %s (%s:%d)\n",
					time.Now().Format("15:04:05"), s.bold(label), peer.IP.String(), peer.Port)
			}
		},
		OnTransferStart: func(transferID string, peerDeviceID string, manifest wire.Manifest) {
			rec, _ := env.TrustStore.GetDevice(ctx, peerDeviceID)
			label := peerDeviceID
			if rec != nil {
				label = rec.LocalLabel
			}
			if *jsonOutput {
				_, _ = fmt.Fprintf(stdout, `{"event":"transfer_started","transfer_id":%q,"peer_device_id":%q,"total_size":%d}`+"\n",
					transferID, peerDeviceID, manifest.TotalSize)
			} else {
				s := newStyleFromWriter(stdout)
				_, _ = fmt.Fprintf(stdout, "[%s] Receiving transfer %s from %s (%d files, %s)...\n",
					time.Now().Format("15:04:05"), s.bold(transferID), s.bold(label), len(manifest.Files), humanBytes(manifest.TotalSize))
			}
		},
		OnProgress: func(peerDeviceID string, ackBytes int64) {
			if *jsonOutput {
				_, _ = fmt.Fprintf(stdout, `{"event":"progress","peer_device_id":%q,"acknowledged_bytes":%d}`+"\n",
					peerDeviceID, ackBytes)
			}
		},
		OnTransferComplete: func(peerDeviceID string, outcome *transfer.Outcome) {
			rec, _ := env.TrustStore.GetDevice(ctx, peerDeviceID)
			label := peerDeviceID
			if rec != nil {
				label = rec.LocalLabel
			}
			if *jsonOutput {
				_, _ = fmt.Fprintf(stdout, `{"event":"transfer_complete","peer_device_id":%q,"name":%q,"size":%d,"digest":%q,"path":%q}`+"\n",
					peerDeviceID, outcome.Name, outcome.Size, outcome.Digest, outcome.Path)
			} else {
				s := newStyleFromWriter(stdout)
				_, _ = fmt.Fprintf(stdout, "[%s] Transfer complete from %s: %s (%s) -> %s\n",
					time.Now().Format("15:04:05"), s.bold(label), s.bold(outcome.Name), humanBytes(outcome.Size), outcome.Path)
				_, _ = fmt.Fprintf(stdout, "[%s] Whole-file SHA-256: %s (%s)\n",
					time.Now().Format("15:04:05"), s.bold(outcome.Digest), s.green("Verified"))
			}
		},
		OnTransferError: func(peerDeviceID string, err error) {
			if *jsonOutput {
				_, _ = fmt.Fprintf(stdout, `{"event":"transfer_error","peer_device_id":%q,"error":%q}`+"\n",
					peerDeviceID, err.Error())
			} else {
				s := newStyleFromWriter(stdout)
				_, _ = fmt.Fprintf(stdout, "[%s] %s with peer %s: %v\n",
					time.Now().Format("15:04:05"), s.red("Transfer error"), peerDeviceID, err)
			}
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer func() { _ = listener.Close() }()

	if !*jsonOutput {
		s := newStyleFromWriter(stdout)
		_, _ = fmt.Fprintln(stdout, s.bold("SendBeam Trusted Listener"))
		_, _ = fmt.Fprintf(stdout, "Destination: %s\n", absDest)
		if *autoAccept {
			_, _ = fmt.Fprintln(stdout, "Auto-Accept: Enabled for trusted devices")
		} else {
			_, _ = fmt.Fprintln(stdout, "Auto-Accept: Disabled (prompts required)")
		}
		_, _ = fmt.Fprintln(stdout, "Listening for local network beacons and trusted connections...")
		_, _ = fmt.Fprintln(stdout, s.dim("Press Ctrl+C to stop."))
	}

	startErr := listener.Start(ctx)
	if startErr != nil && !errors.Is(startErr, context.Canceled) && !errors.Is(startErr, context.DeadlineExceeded) {
		_, _ = fmt.Fprintf(stderr, "listener error: %v\n", startErr)
		return 1
	}

	if *once && listener.VerifiedDeliveries() >= 1 && !*jsonOutput {
		s := newStyleFromWriter(stdout)
		_, _ = fmt.Fprintln(stdout, s.green("Single verified delivery completed. Exiting."))
	}

	return 0
}
