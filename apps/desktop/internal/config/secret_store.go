// Package config manages desktop persistent configuration and credentials.
package config

import (
	"github.com/sendbeam/engine/trust"
)

// SecretStore aliases trust.SecretStore for desktop credential storage.
type SecretStore = trust.SecretStore

var (
	// ErrSecretStoreUnavailable is returned when attempting to persist secrets on a
	// system where OS-protected credential storage is unavailable. Silent downgrade
	// to plaintext persistence is strictly refused.
	ErrSecretStoreUnavailable = trust.ErrSecretStoreUnavailable
	// ErrSecretNotFound is returned when the requested secret key does not exist.
	ErrSecretNotFound = trust.ErrSecretNotFound
)

// UnavailableSecretStore aliases trust.UnavailableSecretStore.
type UnavailableSecretStore = trust.UnavailableSecretStore

// MemorySecretStore aliases trust.MemorySecretStore.
type MemorySecretStore = trust.MemorySecretStore

// DarwinKeychainSecretStore aliases trust.DarwinKeychainSecretStore.
type DarwinKeychainSecretStore = trust.DarwinKeychainSecretStore

// LinuxSecretServiceStore aliases trust.LinuxSecretServiceStore.
type LinuxSecretServiceStore = trust.LinuxSecretServiceStore

// WindowsDPAPIStore aliases trust.WindowsDPAPIStore.
type WindowsDPAPIStore = trust.WindowsDPAPIStore

// NewUnavailableSecretStore aliases trust.NewUnavailableSecretStore.
var NewUnavailableSecretStore = trust.NewUnavailableSecretStore

// NewMemorySecretStore aliases trust.NewMemorySecretStore.
var NewMemorySecretStore = trust.NewMemorySecretStore

// NewDarwinKeychainSecretStore aliases trust.NewDarwinKeychainSecretStore.
var NewDarwinKeychainSecretStore = trust.NewDarwinKeychainSecretStore

// NewLinuxSecretServiceStore aliases trust.NewLinuxSecretServiceStore.
var NewLinuxSecretServiceStore = trust.NewLinuxSecretServiceStore

// NewWindowsDPAPIStore aliases trust.NewWindowsDPAPIStore.
var NewWindowsDPAPIStore = trust.NewWindowsDPAPIStore

// DefaultSecretStore aliases trust.DefaultSecretStore.
var DefaultSecretStore = trust.DefaultSecretStore

// EncodeDPAPICiphertextBlob aliases trust.EncodeDPAPICiphertextBlob.
var EncodeDPAPICiphertextBlob = trust.EncodeDPAPICiphertextBlob

// DecodeDPAPICiphertextBlob aliases trust.DecodeDPAPICiphertextBlob.
var DecodeDPAPICiphertextBlob = trust.DecodeDPAPICiphertextBlob
