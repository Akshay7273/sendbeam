package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sendbeam/engine/migrate"
)

// onboardResult is the structured output of `sendbeam onboard --json`.
type onboardResult struct {
	NewIdentity   bool   `json:"new_identity"`
	DeviceID      string `json:"device_id"`
	Fingerprint   string `json:"fingerprint"`
	ConfigDir     string `json:"config_dir"`
	PairedDevices int    `json:"paired_devices"`
	StateVersion  int    `json:"state_version"`
}

// runOnboard implements `sendbeam onboard`: first-run setup on the real
// production path. It runs v2.0 state migrations, loads or creates the device
// identity (never silently regenerating a corrupt one), then reports what
// this device is and what to do next. It is idempotent: running it again
// keeps the same identity.
func runOnboard(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("onboard", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var configDir string
	var jsonOut bool
	fs.StringVar(&configDir, "config-dir", "", "override the SendBeam config directory")
	fs.BoolVar(&jsonOut, "json", false, "print structured JSON result")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// InitCLIEnvironment runs the v2.0 state migrations (with rollback and
	// newer-state quarantine) before any store is opened.
	env, err := InitCLIEnvironment(configDir)
	if err != nil {
		fmt.Fprintf(stderr, "sendbeam onboard: %v\n", err)
		return 1
	}

	// Record whether an identity already existed so the report is honest
	// about creation versus reuse.
	idPath := filepath.Join(env.ConfigDir, identityKeyFileName)
	_, statErr := os.Stat(idPath)
	newIdentity := os.IsNotExist(statErr)

	ctx := context.Background()
	id, err := env.IdentityMgr.GetOrCreateIdentity()
	if err != nil {
		// Fail closed: a corrupt identity.key is never silently replaced.
		fmt.Fprintf(stderr, "sendbeam onboard: cannot load device identity: %v\n", err)
		return 1
	}

	devices, err := env.TrustStore.ListDevices(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "sendbeam onboard: cannot list trusted devices: %v\n", err)
		return 1
	}

	res := onboardResult{
		NewIdentity:   newIdentity,
		DeviceID:      id.DeviceID,
		Fingerprint:   id.Fingerprint,
		ConfigDir:     env.ConfigDir,
		PairedDevices: len(devices),
		StateVersion:  migrate.CurrentVersion,
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "sendbeam onboard: encode result: %v\n", err)
			return 1
		}
		return 0
	}

	s := newStyleFromWriter(stdout)
	if newIdentity {
		fmt.Fprintln(stdout, s.bold("Welcome to SendBeam — this device now has an identity."))
	} else {
		fmt.Fprintln(stdout, s.bold("Welcome back — this device already has an identity."))
	}
	fmt.Fprintln(stdout)
	fmt.Fprintf(stdout, "  Device ID:   %s\n", s.cyan(res.DeviceID))
	fmt.Fprintf(stdout, "  Fingerprint: %s\n", s.cyan(res.Fingerprint))
	fmt.Fprintf(stdout, "  Config dir:  %s\n", res.ConfigDir)
	fmt.Fprintf(stdout, "  Paired devices: %d\n", res.PairedDevices)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, s.bold("Next steps:"))
	fmt.Fprintln(stdout, "  1. Pair another device:  "+s.cyan("sendbeam pair"))
	fmt.Fprintln(stdout, "  2. Listen for incoming:  "+s.cyan("sendbeam listen"))
	fmt.Fprintln(stdout, "  3. Send a file:          "+s.cyan("sendbeam send <file>"))
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, s.dim("Your files stay on this device. The sender must be running and the recipient reachable — there is no cloud inbox."))
	return 0
}
