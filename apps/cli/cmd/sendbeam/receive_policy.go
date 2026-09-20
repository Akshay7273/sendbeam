// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sendbeam/engine/receiver"
)

// runReceivePolicy implements `sendbeam receive-policy`: inspect and change
// the routine-aware auto-accept policy (V22-PR06). The policy is OFF by
// default — every incoming transfer goes to manual consent — and only
// accepts transfers that (a) carry a valid routine provenance, (b) come
// from an explicitly allowlisted sender device, and (c) pass the same
// trust and tombstone validation as every other transfer.
//
// Usage:
//
//	sendbeam receive-policy show [--json]
//	sendbeam receive-policy set [--enable|--disable] [--allow-routine=true|false]
//	    [--allow-device ID ...] [--clear-devices]
func runReceivePolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		receivePolicyUsage(stderr)
		return 2
	}
	switch args[0] {
	case "show":
		return runReceivePolicyShow(args[1:], stdout, stderr)
	case "set":
		return runReceivePolicySet(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		receivePolicyUsage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "sendbeam receive-policy: unknown subcommand %q\n\n", args[0])
		receivePolicyUsage(stderr)
		return 2
	}
}

func receivePolicyUsage(w io.Writer) {
	s := newStyleFromWriter(w)
	_, _ = fmt.Fprintln(w, s.bold("sendbeam receive-policy")+" — routine auto-accept policy (opt-in, default off)")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam receive-policy show")+" [--json]")
	_, _ = fmt.Fprintln(w, "  "+s.cyan("sendbeam receive-policy set")+" [--enable|--disable] [--allow-routine=true|false] [--allow-device ID ...] [--clear-devices]")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "When enabled, transfers that carry a saved routine's origin label")
	_, _ = fmt.Fprintln(w, "from an allowlisted device skip the consent prompt. Everything else —")
	_, _ = fmt.Fprintln(w, "one-off sends, unlisted senders, revoked devices — still needs consent.")
}

// effectiveConfigDirForSettings resolves the directory the CLI settings
// live in: the explicit --config-dir flag, or the user's app config dir.
func effectiveConfigDirForSettings(configDir string) string {
	if configDir != "" {
		return configDir
	}
	userConfig, err := os.UserConfigDir()
	if err != nil {
		userConfig = "."
	}
	return filepath.Join(userConfig, appConfigDirName)
}

// effectiveAutoAcceptPolicy returns the stored policy or the safe zero
// value (disabled) when nothing is stored yet. A stored policy that
// fails validation is treated as absent: the policy fails closed rather
// than letting a malformed allowlist govern auto-accept.
func effectiveAutoAcceptPolicy(configDir string) receiver.AutoAcceptPolicy {
	s := loadCLISettings(configDir)
	if s.AutoAcceptPolicy == nil {
		return receiver.AutoAcceptPolicy{}
	}
	if err := receiver.ValidateAutoAcceptPolicy(*s.AutoAcceptPolicy); err != nil {
		return receiver.AutoAcceptPolicy{}
	}
	return *s.AutoAcceptPolicy
}

func runReceivePolicyShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receive-policy show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print the policy as JSON")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	_ = parseArgs(fs, args)

	p := effectiveAutoAcceptPolicy(effectiveConfigDirForSettings(*configDir))
	if *jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(p)
		return 0
	}
	s := newStyleFromWriter(stdout)
	state := s.dim("off")
	if p.Enabled {
		state = s.green("on")
	}
	_, _ = fmt.Fprintf(stdout, "Routine auto-accept: %s\n", state)
	_, _ = fmt.Fprintf(stdout, "  Allow routine transfers: %v\n", p.AllowRoutineTransfers)
	if len(p.AllowedDevices) == 0 {
		_, _ = fmt.Fprintln(stdout, "  Allowed devices: (none — nothing auto-accepts)")
	} else {
		_, _ = fmt.Fprintf(stdout, "  Allowed devices (%d):\n", len(p.AllowedDevices))
		for _, id := range p.AllowedDevices {
			_, _ = fmt.Fprintf(stdout, "    • %s\n", id)
		}
	}
	if !p.Enabled {
		_, _ = fmt.Fprintln(stdout, s.dim("Every incoming transfer goes to manual consent."))
	}
	return 0
}

// stringSliceFlag collects repeatable --allow-device flags.
type stringSliceFlag struct{ vals []string }

func (f *stringSliceFlag) String() string     { return strings.Join(f.vals, ",") }
func (f *stringSliceFlag) Set(v string) error { f.vals = append(f.vals, v); return nil }

func runReceivePolicySet(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receive-policy set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	enable := fs.Bool("enable", false, "turn routine auto-accept on")
	disable := fs.Bool("disable", false, "turn routine auto-accept off")
	allowRoutine := fs.Bool("allow-routine", true, "allow provenance-carrying transfers to skip consent")
	clearDevices := fs.Bool("clear-devices", false, "empty the allowed-devices list")
	var allowDevices stringSliceFlag
	fs.Var(&allowDevices, "allow-device", "allowlist one sender device id (repeatable; replaces the list)")
	_ = parseArgs(fs, args)

	if *enable && *disable {
		_, _ = fmt.Fprintln(stderr, "sendbeam receive-policy set: --enable and --disable are mutually exclusive")
		return 2
	}

	configPath := effectiveConfigDirForSettings(*configDir)
	p := effectiveAutoAcceptPolicy(configPath)
	switch {
	case *enable:
		p.Enabled = true
		// Enabling fresh also allows routine transfers unless the user
		// explicitly said otherwise: an enabled-but-empty policy would
		// accept nothing, which is never what --enable means.
		p.AllowRoutineTransfers = *allowRoutine
	case *disable:
		p.Enabled = false
	}
	// --allow-routine=false narrows an enabled policy without disabling it.
	if !*enable && !*disable && !*allowRoutine {
		p.AllowRoutineTransfers = false
	}
	switch {
	case *clearDevices:
		p.AllowedDevices = nil
	case len(allowDevices.vals) > 0:
		p.AllowedDevices = append([]string{}, allowDevices.vals...)
	}
	if err := receiver.ValidateAutoAcceptPolicy(p); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam receive-policy set: %v\n", err)
		return 1
	}
	settings := loadCLISettings(configPath)
	settings.AutoAcceptPolicy = &p
	if err := os.MkdirAll(configPath, 0o700); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam receive-policy set: %v\n", err)
		return 1
	}
	if err := saveCLISettings(configPath, settings); err != nil {
		_, _ = fmt.Fprintf(stderr, "sendbeam receive-policy set: %v\n", err)
		return 1
	}
	s := newStyleFromWriter(stdout)
	state := s.dim("off")
	if p.Enabled {
		state = s.green("on")
	}
	_, _ = fmt.Fprintf(stdout, "Routine auto-accept policy saved: %s (%d allowed device(s)).\n", state, len(p.AllowedDevices))
	return 0
}
