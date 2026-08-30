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

	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/engine/transfer"
	"github.com/sendbeam/wire"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ", ")
}

func (s *stringList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func runSend(args []string) int {
	return executeSend(args, os.Stdout, os.Stderr)
}

func executeSend(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(stderr)

	server := fs.String("server", defaultServer, "signaling server URL")
	insecure := fs.Bool("insecure-skip-verify", false, "skip TLS verification (self-signed dev certs only)")
	words := fs.Int("words", 0, "number of words in the invite code (0 = default)")
	var toDevices stringList
	fs.Var(&toDevices, "to", "send directly to trusted device name, ID, or fingerprint (repeatable or comma-separated)")
	relayOnly := fs.Bool("relay-only", false, "force the encrypted WebSocket relay")
	var iceServer iceServerList
	fs.Var(&iceServer, "ice-server", "STUN server URL for direct-path candidates (repeatable; default stun:stun.l.google.com:19302)")
	privateMode := fs.Bool("private", false, "enable negotiated traffic padding for wire privacy")
	jitter := fs.Duration("jitter", 0, "maximum random scheduling jitter for relay frames (e.g. 15ms)")
	jsonOutput := fs.Bool("json", false, "output structured JSON result")
	concurrency := fs.Int("concurrency", 4, "maximum concurrent target transfers")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")

	rawPositionals := parseArgs(fs, args)

	var filePaths []string
	for _, pos := range rawPositionals {
		if strings.HasPrefix(pos, "@") {
			toDevices = append(toDevices, strings.TrimPrefix(pos, "@"))
		} else {
			filePaths = append(filePaths, pos)
		}
	}

	if len(filePaths) == 0 {
		_, _ = fmt.Fprintln(stderr, "sendbeam send: a file to send is required")
		return 2
	}

	if len(toDevices) == 0 {
		return runSingleInteractiveSend(filePaths, *server, *insecure, *words, *relayOnly, iceServer, *privateMode, *jitter, *jsonOutput, stdout, stderr)
	}

	return runBroadcastSend(filePaths, toDevices, *server, *insecure, *relayOnly, iceServer, *privateMode, *jitter, *jsonOutput, *concurrency, *configDir, stdout, stderr)
}

func runSingleInteractiveSend(filePaths []string, server string, insecure bool, words int, relayOnly bool, iceServer iceServerList, privateMode bool, jitter time.Duration, jsonOutput bool, stdout, stderr io.Writer) int {
	ice, err := iceServers(iceServer)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %s\n", err)
		return 2
	}
	sources, totalSize, err := transfer.NewOSFileSources(filePaths)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %s\n", err)
		return 1
	}

	senderDir, err := transfer.SenderStoreDir()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %s\n", err)
		return 1
	}
	senderStore, err := transfer.OpenSenderStore(senderDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %s\n", err)
		return 1
	}
	transferID, onSendManifest, reused, err := transfer.PrepareSender(senderStore, filePaths, sources)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %s\n", err)
		return 1
	}

	session := rendezvous.Options{
		Role:      rendezvous.RoleOfferer,
		WordCount: words,
		OnCode:    codePrinter(server),
		OnPhase:   phasePrinter(rendezvous.RoleOfferer),
	}
	var resumeCtx *transfer.ResumeContext
	if reused {
		srec, ok, lookupErr := senderStore.Lookup(transfer.PathKey(filePaths))
		if lookupErr != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam send: %s\n", lookupErr)
			return 1
		}
		if !ok {
			_, _ = fmt.Fprintf(stderr, "sendbeam send: the sender record for the interrupted transfer vanished; the source cannot be verified — nothing was sent. Start fresh or discard any receiver-side state.\n")
			return 1
		}
		if srec.ResumeSecret == nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam send: the sender record for transfer %s carries no resume credential (legacy pre-PR07 state); authenticated cross-session resume is unavailable and the transfer id cannot be reused — nothing was sent. Discard the record with %q and send fresh.\n",
				srec.TransferID, "sendbeam transfers discard "+srec.TransferID)
			return 1
		}
		secret, err := wire.DecodeResumeSecretEnvelope(srec.ResumeSecret)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam send: sender record %s has a corrupt resume credential (%v); refusing to reuse the id — discard the record with %q\n",
				srec.TransferID, err, "sendbeam transfers discard "+srec.TransferID)
			return 1
		}
		resumeCtx = &transfer.ResumeContext{
			TransferID:          srec.TransferID,
			ManifestFingerprint: srec.ManifestFingerprint,
			Role:                wire.RoleOfferer,
			ResumeSecret:        secret,
		}
		caps := rendezvous.DefaultCaps()
		caps.Features = append(caps.Features, wire.ResumeAuthCapability)
		session.LocalCaps = &caps
		s := newStyleFromWriter(stderr)
		_, _ = fmt.Fprintln(stderr, s.dim("Interrupted transfer "+transferID+" — resuming requires authenticating with the original receiver before any verified progress is reused."))
	}

	progressFiles := make([]progressFile, len(sources))
	for i, source := range sources {
		meta := source.Meta()
		progressFiles[i] = progressFile{name: meta.Name, size: meta.Size}
	}
	label := progressFiles[0].name
	if len(progressFiles) > 1 {
		label = fmt.Sprintf("%d files", len(progressFiles))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := dial(ctx, server, insecure)
	if err != nil {
		s := newStyleFromWriter(stderr)
		_, _ = fmt.Fprintf(stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
		return 1
	}
	defer client.Close()

	progress := newProgress(totalSize)
	progress.setFiles(progressFiles)
	start := time.Now()
	out, err := transfer.Run(ctx, client, transfer.Spec{
		Session:        session,
		Sources:        sources,
		TransferID:     transferID,
		OnSendManifest: onSendManifest,
		OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
			return senderStore.AttachResumeSecret(manifest, resumeRoot, !reused)
		},
		Resume: resumeCtx,
		OnResume: func(r transfer.ResumeResult) {
			s := newStyleFromWriter(stderr)
			if r.Authenticated {
				_, _ = fmt.Fprintln(stderr, s.check("Authenticated with the original receiver — resuming from the verified checkpoint with fresh keys."))
			} else if r.Attempted {
				_, _ = fmt.Fprintln(stderr, s.cyan("Authenticating the interrupted transfer with the receiver …"))
			}
		},
		ForceRelay:       relayOnly,
		Private:          privateMode,
		RelayJitter:      jitter,
		ICEServers:       ice,
		OnTransport:      transportPrinter,
		OnConnect:        connectPrinter(fmt.Sprintf("Sending %s (%s) …", label, humanBytes(totalSize))),
		OnFileProgress:   progress.reportFile,
		OnResumeProgress: progress.setReused,
		OnControls:       terminalControls(),
		OnStateChange:    progress.setState,
	})
	dur := time.Since(start).Milliseconds()
	progress.finish()
	s := newStyleFromWriter(stderr)
	if err != nil {
		if jsonOutput {
			status, errMsg := transfer.ClassifyBroadcastError(err)
			res := transfer.BroadcastResult{
				Results: []transfer.TargetResult{
					{
						TargetID:   "anonymous",
						Label:      "anonymous",
						Status:     status,
						DurationMs: dur,
						Error:      errMsg,
					},
				},
				AllOk: false,
			}
			data, _ := json.MarshalIndent(res, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		} else {
			_, _ = fmt.Fprintf(stderr, "\n%s\n", s.cross("Failed: "+handshakeError(err)))
			if srec, ok, lookupErr := senderStore.Lookup(transfer.PathKey(filePaths)); lookupErr == nil && ok {
				_, _ = fmt.Fprintf(stderr, "%s\n", s.dim("Sender state for transfer "+srec.TransferID+" was kept; re-run this command to resume it with the same receiver."))
			}
		}
		return 1
	}

	if srec, ok, lookupErr := senderStore.Lookup(transfer.PathKey(filePaths)); lookupErr == nil && ok {
		if err := senderStore.Discard(srec.TransferID); err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam send: warning: could not discard sender record %s: %v\n", srec.TransferID, err)
		}
	}

	if jsonOutput {
		res := transfer.BroadcastResult{
			Results: []transfer.TargetResult{
				{
					TargetID:   "anonymous",
					Label:      "anonymous",
					Status:     transfer.StatusOk,
					Digest:     out.Digest,
					Size:       out.Size,
					DurationMs: dur,
					Outcome:    out,
				},
			},
			AllOk: true,
		}
		data, _ := json.MarshalIndent(res, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
		return 0
	}

	_, _ = fmt.Fprintln(stdout)
	if len(out.Files) == 1 {
		_, _ = fmt.Fprintln(stdout, s.green("✓")+" Sent "+s.bold(out.Name)+" ("+humanBytes(out.Size)+").")
	} else {
		_, _ = fmt.Fprintln(stdout, s.green("✓")+" Sent "+s.bold(fmt.Sprintf("%d files", len(out.Files)))+" ("+humanBytes(out.Size)+").")
	}
	_, _ = fmt.Fprintf(stdout, "  %s  %s\n", s.grey("Fingerprint:"), fingerprint(out.Handshake.Master))
	if len(out.Files) == 1 {
		_, _ = fmt.Fprintf(stdout, "  %s  %s\n", s.grey("SHA-256:"), out.Digest)
	} else {
		_, _ = fmt.Fprintf(stdout, "  %s  %s\n", s.grey("File-set SHA-256:"), out.Digest)
	}
	return 0
}

func runBroadcastSend(filePaths []string, toDevices []string, server string, insecure bool, relayOnly bool, iceServer iceServerList, privateMode bool, jitter time.Duration, jsonOutput bool, concurrency int, configDir string, stdout, stderr io.Writer) int {
	env, err := InitCLIEnvironment(configDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ice, err := iceServers(iceServer)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %s\n", err)
		return 2
	}
	sources, totalSize, err := transfer.NewOSFileSources(filePaths)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam send: %s\n", err)
		return 1
	}

	type resolvedDev struct {
		targetName string
		record     *wire.TrustRecord
	}
	var resolved []resolvedDev

	for _, tName := range toDevices {
		dev, err := ResolveDevice(ctx, env.TrustStore, tName)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "sendbeam send: %v\n", err)
			return 1
		}
		if dev.Revoked {
			_, _ = fmt.Fprintf(stderr, "sendbeam send: trust for device %q is revoked\n", dev.LocalLabel)
			return 1
		}
		resolved = append(resolved, resolvedDev{targetName: tName, record: dev})
	}

	s := newStyleFromWriter(stderr)
	if !jsonOutput {
		if len(resolved) == 1 {
			_, _ = fmt.Fprintf(stderr, "Sending to trusted device %s (%s)...\n", s.bold(resolved[0].record.LocalLabel), resolved[0].record.Fingerprint())
		} else {
			_, _ = fmt.Fprintf(stderr, "Broadcasting to %d trusted devices (concurrency: %d)...\n", len(resolved), concurrency)
		}
	}

	targets := make([]transfer.BroadcastTarget, len(resolved))
	for i, r := range resolved {
		var sig transfer.Signal
		client, err := dial(ctx, server, insecure)
		if err != nil {
			sig = &offlineSignal{err: fmt.Errorf("peer offline: %w", err)}
		} else {
			sig = client
		}

		session := rendezvous.Options{
			Role: rendezvous.RoleOfferer,
		}

		targets[i] = transfer.BroadcastTarget{
			ID:     r.record.DeviceID,
			Label:  r.record.LocalLabel,
			Signal: sig,
			Spec: transfer.Spec{
				Session:     session,
				Sources:     sources,
				ICEServers:  ice,
				ForceRelay:  relayOnly,
				Private:     privateMode,
				RelayJitter: jitter,
			},
		}
	}

	broadcastResult := transfer.RunBroadcast(ctx, targets, transfer.BroadcastOptions{
		Concurrency: concurrency,
		OnTargetStart: func(target transfer.BroadcastTarget) {
			if !jsonOutput {
				_, _ = fmt.Fprintf(stderr, "[%s] Starting transfer to %s...\n", time.Now().Format("15:04:05"), s.cyan(target.Label))
			}
		},
		OnTargetComplete: func(_ string, res transfer.TargetResult) {
			if !jsonOutput {
				if res.Status == transfer.StatusOk {
					_, _ = fmt.Fprintf(stderr, "[%s] ✓ %s: completed in %dms\n", time.Now().Format("15:04:05"), s.green(res.Label), res.DurationMs)
				} else {
					_, _ = fmt.Fprintf(stderr, "[%s] ✗ %s: %s (%s)\n", time.Now().Format("15:04:05"), s.red(res.Label), res.Status, res.Error)
				}
			}
		},
	})

	if jsonOutput {
		data, _ := json.MarshalIndent(broadcastResult, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		renderBroadcastTable(stdout, broadcastResult.Results, totalSize)
	}

	if broadcastResult.AllOk {
		return 0
	}
	return 1
}

func renderBroadcastTable(w io.Writer, results []transfer.TargetResult, totalSize int64) {
	s := newStyleFromWriter(w)
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, s.bold("Broadcast Transfer Summary"))
	_, _ = fmt.Fprintln(w, strings.Repeat("─", 78))
	_, _ = fmt.Fprintf(w, "%-20s %-10s %-14s %-12s %s\n", "TARGET", "STATUS", "TRANSFERRED", "DURATION", "SHA-256")
	_, _ = fmt.Fprintln(w, strings.Repeat("─", 78))

	succeeded := 0
	for _, r := range results {
		var statusStr string
		switch r.Status {
		case transfer.StatusOk:
			statusStr = s.green("ok")
			succeeded++
		case transfer.StatusRefused:
			statusStr = s.yellow("refused")
		case transfer.StatusOffline:
			statusStr = s.grey("offline")
		default:
			statusStr = s.red("failed")
		}

		transferred := "-"
		if r.Status == transfer.StatusOk {
			transferred = humanBytes(totalSize)
		}
		digest := "-"
		if r.Digest != "" {
			if len(r.Digest) > 16 {
				digest = r.Digest[:16] + "…"
			} else {
				digest = r.Digest
			}
		}
		durStr := fmt.Sprintf("%dms", r.DurationMs)
		if r.DurationMs >= 1000 {
			durStr = fmt.Sprintf("%.2fs", float64(r.DurationMs)/1000.0)
		}

		_, _ = fmt.Fprintf(w, "%-20s %-10s %-14s %-12s %s\n", "@"+r.Label, statusStr, transferred, durStr, digest)
	}
	_, _ = fmt.Fprintln(w, strings.Repeat("─", 78))
	if succeeded == len(results) {
		_, _ = fmt.Fprintf(w, "%s All %d transfers completed successfully.\n", s.green("✓"), len(results))
	} else {
		_, _ = fmt.Fprintf(w, "%s %d succeeded, %d failed.\n", s.yellow("!"), succeeded, len(results)-succeeded)
	}
	_, _ = fmt.Fprintln(w)
}

type offlineSignal struct {
	err error
}

func (s *offlineSignal) Send(rendezvous.Message) error { return s.err }
func (s *offlineSignal) SendBinary([]byte) error       { return s.err }
func (s *offlineSignal) Run(context.Context, func(rendezvous.Message), func([]byte)) error {
	return s.err
}
func (s *offlineSignal) Close() {}
