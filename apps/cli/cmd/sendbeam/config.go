// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/sendbeam/engine/netpolicy"
)

func runConfig(args []string) int {
	return executeConfig(args, os.Stdout, os.Stderr)
}

func executeConfig(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	set := fs.String("set-network-policy", "", "persist network policy: online, prefer-local, local-only")
	configDir := fs.String("config-dir", "", "path to custom configuration directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	env, err := InitCLIEnvironment(*configDir)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	if *set != "" {
		p, err := netpolicy.Parse(*set)
		if err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
		s := loadCLISettings(env.ConfigDir)
		s.NetworkPolicy = p.String()
		if err := saveCLISettings(env.ConfigDir, s); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Network policy set to %s\n", p.String())
		return 0
	}
	p, _ := resolveNetworkPolicy("", env.ConfigDir)
	fmt.Fprintf(stdout, "network-policy: %s\n", p.String())
	fmt.Fprintln(stdout, "")
	fmt.Fprintln(stdout, "Policies:")
	fmt.Fprintln(stdout, "  online       default v2.0 behavior; online services available")
	fmt.Fprintln(stdout, "  prefer-local try local paths first, then online")
	fmt.Fprintln(stdout, "  local-only   only local paths; fails closed without a local route")
	return 0
}
