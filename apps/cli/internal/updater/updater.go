// Package updater provides CLI updater integration re-exported from packages/engine/updater.
package updater

import "github.com/sendbeam/engine/updater"

type (
	// Version represents a parsed SemVer release version.
	Version = updater.Version
	// Channel represents an update channel.
	Channel = updater.Channel
	// ReleaseAsset represents an update asset.
	ReleaseAsset = updater.ReleaseAsset
	// ReleaseMetadata contains release metadata.
	ReleaseMetadata = updater.ReleaseMetadata
	// ChannelManifest contains signed channel manifest data.
	ChannelManifest = updater.ChannelManifest
	// CheckResult contains update check outcomes.
	CheckResult = updater.CheckResult
	// Updater coordinates updates.
	Updater = updater.Updater
	// Option configures an Updater.
	Option = updater.Option
	// ApplyOptions configures atomic binary replacement.
	ApplyOptions = updater.ApplyOptions
	// DesktopApplyOptions configures desktop application updates.
	DesktopApplyOptions = updater.DesktopApplyOptions
	// DesktopApplyResult describes desktop update results.
	DesktopApplyResult = updater.DesktopApplyResult
	// ProductKind identifies CLI vs Desktop products.
	ProductKind = updater.ProductKind
)

// Constants re-exported from packages/engine/updater
const (
	ChannelStable            = updater.ChannelStable
	ChannelBeta              = updater.ChannelBeta
	ChannelDev               = updater.ChannelDev
	ProductKindCLI           = updater.ProductKindCLI
	ProductKindDesktop       = updater.ProductKindDesktop
	DefaultMinisignPublicKey = updater.DefaultMinisignPublicKey
	DefaultUpdateBaseURL     = updater.DefaultUpdateBaseURL
)

// Errors re-exported from packages/engine/updater
var (
	ErrInvalidSignature        = updater.ErrInvalidSignature
	ErrDowngradeRejected       = updater.ErrDowngradeRejected
	ErrManifestMalformed       = updater.ErrManifestMalformed
	ErrChannelMismatch         = updater.ErrChannelMismatch
	ErrNoUpdateAvailable       = updater.ErrNoUpdateAvailable
	ErrManagedByPackageManager = updater.ErrManagedByPackageManager
	ErrChecksumMismatch        = updater.ErrChecksumMismatch
	ErrBinaryNotFoundInArchive = updater.ErrBinaryNotFoundInArchive
)

// Functions re-exported from packages/engine/updater
var (
	New                        = updater.New
	ParseVersion               = updater.ParseVersion
	ParseChannel               = updater.ParseChannel
	ParseChecksums             = updater.ParseChecksums
	ApplyUpdate                = updater.ApplyUpdate
	ApplyDesktopUpdate         = updater.ApplyDesktopUpdate
	DetectPackageManager       = updater.DetectPackageManager
	ResolveDesktopTarget       = updater.ResolveDesktopTarget
	VerifyMinisignSignature    = updater.VerifyMinisignSignature
	SignMinisign               = updater.SignMinisign
	ParseMinisignPublicKey     = updater.ParseMinisignPublicKey
	ParseMinisignSignature     = updater.ParseMinisignSignature
	TargetCLIArchiveName       = updater.TargetCLIArchiveName
	TargetCLIBinaryName        = updater.TargetCLIBinaryName
	TargetDesktopAssetName     = updater.TargetDesktopAssetName
	CurrentPlatformArchiveName = updater.CurrentPlatformArchiveName
	WithProductKind            = updater.WithProductKind
	WithChannel                = updater.WithChannel
	WithBaseURL                = updater.WithBaseURL
	WithGitHubAPI              = updater.WithGitHubAPI
	WithMinisignPublicKey      = updater.WithMinisignPublicKey
	WithHTTPClient             = updater.WithHTTPClient
	WithExecutablePath         = updater.WithExecutablePath
	WithTargetPlatform         = updater.WithTargetPlatform
	WithDesktopFormat          = updater.WithDesktopFormat
)
