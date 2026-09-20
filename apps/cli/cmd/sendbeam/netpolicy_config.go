// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/sendbeam/engine/netpolicy"
	"github.com/sendbeam/engine/receiver"
)

const cliConfigFileName = "config.json"

type cliSettings struct {
	NetworkPolicy string `json:"network_policy,omitempty"`
	// AutoAcceptPolicy is the routine-aware auto-accept policy (V22-PR06):
	// nil/zero means routine auto-accept is off and every transfer goes
	// to manual consent. Stored 0600 alongside the other CLI settings.
	AutoAcceptPolicy *receiver.AutoAcceptPolicy `json:"auto_accept_policy,omitempty"`
}

func loadCLISettings(configDir string) cliSettings {
	var s cliSettings
	if configDir == "" {
		return s
	}
	data, err := os.ReadFile(filepath.Join(configDir, cliConfigFileName))
	if err != nil {
		return s
	}
	_ = json.Unmarshal(data, &s)
	return s
}

func saveCLISettings(configDir string, s cliSettings) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(configDir, cliConfigFileName), data, 0600)
}

func resolveNetworkPolicy(flagVal, configDir string) (netpolicy.Policy, error) {
	if flagVal != "" {
		return netpolicy.Parse(flagVal)
	}
	if configDir == "" {
		userConfig, err := os.UserConfigDir()
		if err != nil {
			userConfig = "."
		}
		configDir = filepath.Join(userConfig, appConfigDirName)
	}
	s := loadCLISettings(configDir)
	if s.NetworkPolicy != "" {
		return netpolicy.Parse(s.NetworkPolicy)
	}
	return netpolicy.Online, nil
}
