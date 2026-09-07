package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

const (
	appConfigDirName    = "sendbeam"
	trustFileName       = "trust.json"
	identityKeyFileName = "identity.key"
	secretsFileName     = "secrets.json"
)

// FileSecretResolver is an alias to trust.FileSecretStore for headless CLI environments.
type FileSecretResolver = trust.FileSecretStore

// NewFileSecretResolver initializes the secret store from disk.
func NewFileSecretResolver(path string) (*FileSecretResolver, error) {
	return trust.NewFileSecretStore(path)
}

// CLIEnvironment provides shared access to local device identity, trust store, and secret store.
type CLIEnvironment struct {
	ConfigDir   string
	IdentityMgr *trust.IdentityManager
	TrustStore  trust.Store
	Secrets     *FileSecretResolver
}

// InitCLIEnvironment loads or creates the default CLI trust environment.
func InitCLIEnvironment(customDir string) (*CLIEnvironment, error) {
	dir := customDir
	if dir == "" {
		userConfig, err := os.UserConfigDir()
		if err != nil {
			userConfig = "."
		}
		dir = filepath.Join(userConfig, appConfigDirName)
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}

	idPath := filepath.Join(dir, identityKeyFileName)
	idMgr, err := trust.NewIdentityManager(idPath)
	if err != nil {
		return nil, fmt.Errorf("init identity manager: %w", err)
	}

	trustPath := filepath.Join(dir, trustFileName)
	trustStore, err := trust.NewFileTrustStore(trustPath)
	if err != nil {
		return nil, fmt.Errorf("init trust store: %w", err)
	}

	secretsPath := filepath.Join(dir, secretsFileName)
	secrets, err := NewFileSecretResolver(secretsPath)
	if err != nil {
		return nil, fmt.Errorf("init secrets store: %w", err)
	}

	return &CLIEnvironment{
		ConfigDir:   dir,
		IdentityMgr: idMgr,
		TrustStore:  trustStore,
		Secrets:     secrets,
	}, nil
}

// ResolveDevice finds a device in the trust store by device ID, local label, or fingerprint.
func ResolveDevice(ctx context.Context, store trust.Store, query string) (*wire.TrustRecord, error) {
	q := strings.TrimSpace(strings.TrimPrefix(query, "@"))
	if q == "" {
		return nil, errors.New("device query cannot be empty")
	}

	devices, err := store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Exact match on DeviceID
	for _, dev := range devices {
		if strings.EqualFold(dev.DeviceID, q) {
			return dev, nil
		}
	}

	// 2. Exact match on Fingerprint
	for _, dev := range devices {
		if strings.EqualFold(dev.Fingerprint(), q) {
			return dev, nil
		}
	}

	// 3. Exact match on LocalLabel (case-insensitive)
	for _, dev := range devices {
		if strings.EqualFold(dev.LocalLabel, q) {
			return dev, nil
		}
	}

	// 4. Prefix match on DeviceID or Fingerprint
	var prefixMatches []*wire.TrustRecord
	for _, dev := range devices {
		if strings.HasPrefix(strings.ToLower(dev.DeviceID), strings.ToLower(q)) ||
			strings.HasPrefix(strings.ToLower(dev.Fingerprint()), strings.ToLower(q)) ||
			strings.HasPrefix(strings.ToLower(dev.LocalLabel), strings.ToLower(q)) {
			prefixMatches = append(prefixMatches, dev)
		}
	}

	if len(prefixMatches) == 1 {
		return prefixMatches[0], nil
	}
	if len(prefixMatches) > 1 {
		return nil, fmt.Errorf("ambiguous device identifier %q matches %d devices", query, len(prefixMatches))
	}

	return nil, fmt.Errorf("device %q not found in trust store", query)
}
