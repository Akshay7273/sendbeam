package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ProductKind identifies whether the updater targets the CLI or Desktop application.
type ProductKind string

const (
	// ProductKindCLI targets standalone CLI binaries.
	ProductKindCLI ProductKind = "cli"
	// ProductKindDesktop targets desktop application bundles.
	ProductKindDesktop ProductKind = "desktop"
)

// CheckResult contains the evaluated update status.
type CheckResult struct {
	UpdateAvailable     bool          `json:"update_available"`
	CurrentVersion      Version       `json:"current_version"`
	LatestVersion       Version       `json:"latest_version"`
	Channel             Channel       `json:"channel"`
	PublishedAt         time.Time     `json:"published_at"`
	ReleaseNotes        string        `json:"release_notes,omitempty"`
	TargetAsset         *ReleaseAsset `json:"target_asset,omitempty"`
	Message             string        `json:"message"`
	ManagedByPkgManager string        `json:"managed_by_pkg_manager,omitempty"`
}

// Updater coordinates checking, downloading, verifying, and applying updates.
type Updater struct {
	ProductKind       ProductKind
	CurrentVersion    Version
	Channel           Channel
	Repository        string
	BaseURL           string // Default DefaultUpdateBaseURL
	MinisignPublicKey string // Pinned Ed25519 public key
	UseGitHubAPI      bool   // Direct GitHub API releases fallback mode
	HTTPClient        *http.Client
	TargetOS          string
	TargetArch        string
	DesktopFormat     string
	ExecutablePath    string

	mu sync.Mutex
}

// Option configures an Updater.
type Option func(*Updater)

// WithProductKind sets the product type (cli or desktop).
func WithProductKind(kind ProductKind) Option {
	return func(u *Updater) {
		u.ProductKind = kind
	}
}

// WithChannel sets the updater channel.
func WithChannel(ch Channel) Option {
	return func(u *Updater) {
		u.Channel = ch
	}
}

// WithBaseURL overrides the release endpoint base URL.
func WithBaseURL(rawURL string) Option {
	return func(u *Updater) {
		u.BaseURL = rawURL
	}
}

// WithGitHubAPI forces using direct GitHub Releases API mode.
func WithGitHubAPI(enabled bool) Option {
	return func(u *Updater) {
		u.UseGitHubAPI = enabled
	}
}

// WithMinisignPublicKey overrides the public key for manifest signature verification.
func WithMinisignPublicKey(pubKey string) Option {
	return func(u *Updater) {
		u.MinisignPublicKey = pubKey
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(u *Updater) {
		u.HTTPClient = client
	}
}

// WithExecutablePath overrides the target binary path.
func WithExecutablePath(p string) Option {
	return func(u *Updater) {
		u.ExecutablePath = p
	}
}

// WithTargetPlatform sets the OS and architecture.
func WithTargetPlatform(targetOS, targetArch string) Option {
	return func(u *Updater) {
		u.TargetOS = targetOS
		u.TargetArch = targetArch
	}
}

// WithDesktopFormat sets the target format for desktop update assets ("appimage", "installer", "app", "zip").
func WithDesktopFormat(format string) Option {
	return func(u *Updater) {
		u.DesktopFormat = format
	}
}

// New creates a new Updater instance.
func New(currentVerStr string, repo string, opts ...Option) (*Updater, error) {
	ver, err := ParseVersion(currentVerStr)
	if err != nil {
		return nil, fmt.Errorf("parsing current version %q: %w", currentVerStr, err)
	}

	execPath, _ := os.Executable()
	if execPath != "" {
		execPath, _ = filepath.EvalSymlinks(execPath)
	}

	u := &Updater{
		ProductKind:       ProductKindCLI,
		CurrentVersion:    ver,
		Channel:           ChannelStable,
		Repository:        repo,
		BaseURL:           DefaultUpdateBaseURL,
		MinisignPublicKey: DefaultMinisignPublicKey,
		UseGitHubAPI:      false,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		TargetOS:       runtime.GOOS,
		TargetArch:     runtime.GOARCH,
		ExecutablePath: execPath,
	}

	for _, opt := range opts {
		opt(u)
	}

	return u, nil
}

// Check checks for available updates against the configured channel.
func (u *Updater) Check(ctx context.Context) (*CheckResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	res := &CheckResult{
		CurrentVersion: u.CurrentVersion,
		Channel:        u.Channel,
	}

	// Package manager detection for desktop installations
	if u.ProductKind == ProductKindDesktop {
		if pm := DetectPackageManager(u.ExecutablePath); pm != "" {
			res.ManagedByPkgManager = pm
			switch pm {
			case "deb":
				res.Message = "SendBeam Desktop is managed by your system package manager (apt/deb). Run 'sudo apt update && sudo apt upgrade sendbeam-desktop' to upgrade."
			case "brew":
				res.Message = "SendBeam Desktop is managed by Homebrew. Run 'brew upgrade sendbeam' to upgrade."
			case "winget":
				res.Message = "SendBeam Desktop is managed by WinGet. Run 'winget upgrade SendBeam' to upgrade."
			default:
				res.Message = fmt.Sprintf("SendBeam Desktop is managed by package manager %q.", pm)
			}
			return res, nil
		}
	}

	if u.CurrentVersion.IsDev {
		res.Message = fmt.Sprintf("Running development build (%s). Channel: %s.", u.CurrentVersion.String(), u.Channel)
		return res, nil
	}

	// If BaseURL points to GitHub API releases endpoint or UseGitHubAPI is set, use GitHub API releases fetcher
	if u.UseGitHubAPI || strings.Contains(u.BaseURL, "api.github.com") {
		return u.checkGitHubReleases(ctx, res)
	}

	// Production signed channel manifest flow
	manifest, err := u.fetchSignedManifest(ctx)
	if err != nil {
		return nil, err
	}

	targetVer, err := ParseVersion(manifest.Version)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid version %q in manifest: %v", ErrManifestMalformed, manifest.Version, err)
	}

	// Validate channel policy
	if !targetVer.CompatibleWithChannel(u.Channel) {
		return nil, fmt.Errorf("%w: version %s incompatible with channel %s", ErrChannelMismatch, targetVer, u.Channel)
	}

	res.LatestVersion = targetVer
	res.PublishedAt = manifest.PublishedAt
	res.ReleaseNotes = manifest.ReleaseNotes

	// Downgrade protection: candidate version must be strictly greater than active version
	if !targetVer.IsGreaterThan(u.CurrentVersion) {
		res.UpdateAvailable = false
		res.Message = fmt.Sprintf("SendBeam is up to date (version %s on channel %s).", u.CurrentVersion, u.Channel)
		return res, nil
	}

	// Find matching target platform asset
	var asset *ReleaseAsset
	if u.ProductKind == ProductKindDesktop {
		asset, err = manifest.FindDesktopTargetAsset(u.TargetOS, u.TargetArch, u.DesktopFormat)
	} else {
		asset, err = manifest.FindTargetAsset(u.TargetOS, u.TargetArch)
	}
	if err != nil {
		return nil, fmt.Errorf("checking update asset: %w", err)
	}

	res.UpdateAvailable = true
	res.TargetAsset = asset
	res.Message = fmt.Sprintf("Update available: %s → %s (%s)", u.CurrentVersion, targetVer, u.Channel)

	return res, nil
}

// checkGitHubReleases evaluates updates via direct GitHub Releases API.
func (u *Updater) checkGitHubReleases(ctx context.Context, res *CheckResult) (*CheckResult, error) {
	releases, err := u.fetchReleases(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching release information: %w", err)
	}

	if len(releases) == 0 {
		res.Message = "No releases found."
		return res, nil
	}

	var candidate *ReleaseMetadata
	for i := range releases {
		rel := &releases[i]
		if !rel.Version.CompatibleWithChannel(u.Channel) {
			continue
		}
		if candidate == nil || rel.Version.IsGreaterThan(candidate.Version) {
			candidate = rel
		}
	}

	if candidate == nil {
		res.Message = fmt.Sprintf("No releases found matching channel %q.", u.Channel)
		return res, nil
	}

	res.LatestVersion = candidate.Version
	res.PublishedAt = candidate.PublishedAt
	res.ReleaseNotes = candidate.ReleaseNotes

	if !candidate.Version.IsGreaterThan(u.CurrentVersion) {
		res.UpdateAvailable = false
		res.Message = fmt.Sprintf("SendBeam is up to date (version %s on channel %s).", u.CurrentVersion, u.Channel)
		return res, nil
	}

	asset, err := candidate.FindTargetAsset(u.TargetOS, u.TargetArch)
	if err != nil {
		return nil, fmt.Errorf("checking update asset: %w", err)
	}

	res.UpdateAvailable = true
	res.TargetAsset = asset
	res.Message = fmt.Sprintf("Update available: %s → %s (%s)", u.CurrentVersion, candidate.Version, u.Channel)

	return res, nil
}

// fetchSignedManifest downloads <baseURL>/<channel>.json and <baseURL>/<channel>.json.minisig and verifies the signature.
func (u *Updater) fetchSignedManifest(ctx context.Context) (*ChannelManifest, error) {
	channelName := u.Channel.String()
	manifestURL := fmt.Sprintf("%s/%s.json", strings.TrimSuffix(u.BaseURL, "/"), channelName)
	sigURL := fmt.Sprintf("%s/%s.json.minisig", strings.TrimSuffix(u.BaseURL, "/"), channelName)

	// Fetch manifest JSON
	reqJSON, err := http.NewRequestWithContext(ctx, http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating manifest request: %w", err)
	}
	reqJSON.Header.Set("User-Agent", "SendBeam-Updater/"+u.CurrentVersion.String())

	respJSON, err := u.HTTPClient.Do(reqJSON)
	if err != nil {
		return nil, fmt.Errorf("fetching update manifest %s: %w", manifestURL, err)
	}
	defer func() {
		_ = respJSON.Body.Close()
	}()

	if respJSON.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching update manifest failed with HTTP %d %s", respJSON.StatusCode, respJSON.Status)
	}

	manifestBytes, err := io.ReadAll(respJSON.Body)
	if err != nil {
		return nil, fmt.Errorf("reading manifest payload: %w", err)
	}

	// Fetch signature
	reqSig, err := http.NewRequestWithContext(ctx, http.MethodGet, sigURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating signature request: %w", err)
	}
	reqSig.Header.Set("User-Agent", "SendBeam-Updater/"+u.CurrentVersion.String())

	respSig, err := u.HTTPClient.Do(reqSig)
	if err != nil {
		return nil, fmt.Errorf("fetching update manifest signature %s: %w", sigURL, err)
	}
	defer func() {
		_ = respSig.Body.Close()
	}()

	if respSig.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: missing signature file (HTTP %d %s)", ErrInvalidSignature, respSig.StatusCode, respSig.Status)
	}

	sigBytes, err := io.ReadAll(respSig.Body)
	if err != nil {
		return nil, fmt.Errorf("reading signature payload: %w", err)
	}

	// Cryptographic Minisign verification
	if err := VerifyMinisignSignature(manifestBytes, string(sigBytes), u.MinisignPublicKey); err != nil {
		return nil, err
	}

	var manifest ChannelManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("%w: JSON unmarshal error: %v", ErrManifestMalformed, err)
	}

	if manifest.Version == "" {
		return nil, fmt.Errorf("%w: missing version in manifest", ErrManifestMalformed)
	}

	return &manifest, nil
}

// Apply downloads and replaces the active executable or stages the installer.
func (u *Updater) Apply(ctx context.Context, check *CheckResult) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if check == nil || !check.UpdateAvailable || check.TargetAsset == nil {
		return ErrNoUpdateAvailable
	}

	if u.ProductKind == ProductKindDesktop {
		if check.ManagedByPkgManager != "" {
			return fmt.Errorf("%w (%s)", ErrManagedByPackageManager, check.ManagedByPkgManager)
		}
	}

	if u.ExecutablePath == "" {
		return errors.New("cannot determine active executable path for replacement")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, check.TargetAsset.DownloadURL, nil)
	if err != nil {
		return fmt.Errorf("preparing download request: %w", err)
	}
	req.Header.Set("User-Agent", "SendBeam-Updater/"+u.CurrentVersion.String())

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading update artifact: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update download failed with HTTP %d %s", resp.StatusCode, resp.Status)
	}

	if u.ProductKind == ProductKindDesktop {
		desktopOpts := DesktopApplyOptions{
			TargetPath:     u.ExecutablePath,
			TargetOS:       u.TargetOS,
			TargetArch:     u.TargetArch,
			Format:         u.DesktopFormat,
			ExpectedSHA256: check.TargetAsset.SHA256,
			ArchiveName:    check.TargetAsset.Name,
		}
		res, err := ApplyDesktopUpdate(ctx, resp.Body, desktopOpts)
		if err != nil {
			return fmt.Errorf("applying desktop update: %w", err)
		}
		if res != nil && res.InstallerPath != "" {
			// Installer was staged
			return nil
		}
		return nil
	}

	// CLI standalone apply
	applyOpts := ApplyOptions{
		TargetPath:     u.ExecutablePath,
		TargetOS:       u.TargetOS,
		ExpectedSHA256: check.TargetAsset.SHA256,
		ArchiveName:    check.TargetAsset.Name,
	}

	if err := ApplyUpdate(ctx, resp.Body, applyOpts); err != nil {
		return fmt.Errorf("applying update: %w", err)
	}

	return nil
}

// fetchReleases queries releases from the repository.
func (u *Updater) fetchReleases(ctx context.Context) ([]ReleaseMetadata, error) {
	relURL := fmt.Sprintf("%s/repos/%s/releases", strings.TrimSuffix(u.BaseURL, "/"), u.Repository)
	if !strings.HasPrefix(relURL, "http://") && !strings.HasPrefix(relURL, "https://") {
		return nil, fmt.Errorf("invalid base URL %q", u.BaseURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, relURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SendBeam-Updater/"+u.CurrentVersion.String())

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("HTTP %d fetching releases: %s", resp.StatusCode, string(body))
	}

	var ghReleases []struct {
		TagName     string    `json:"tag_name"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
		Body        string    `json:"body"`
		Assets      []struct {
			Name               string `json:"name"`
			Size               int64  `json:"size"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghReleases); err != nil {
		return nil, fmt.Errorf("decoding releases json: %w", err)
	}

	var results []ReleaseMetadata
	for _, gr := range ghReleases {
		ver, err := ParseVersion(gr.TagName)
		if err != nil {
			continue
		}

		var assets []ReleaseAsset
		for _, a := range gr.Assets {
			assets = append(assets, ReleaseAsset{
				Name:        a.Name,
				Size:        a.Size,
				DownloadURL: a.BrowserDownloadURL,
			})
		}

		rel := ReleaseMetadata{
			Version:      ver,
			TagName:      gr.TagName,
			Prerelease:   gr.Prerelease,
			PublishedAt:  gr.PublishedAt,
			ReleaseNotes: gr.Body,
			Assets:       assets,
		}

		// Download SHA256SUMS.txt if present
		for _, a := range gr.Assets {
			if a.Name == "SHA256SUMS.txt" {
				if checksums, err := u.fetchChecksums(ctx, a.BrowserDownloadURL); err == nil {
					rel.Checksums = checksums
				}
				break
			}
		}

		results = append(results, rel)
	}

	return results, nil
}

func (u *Updater) fetchChecksums(ctx context.Context, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SendBeam-Updater/"+u.CurrentVersion.String())

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching checksums", resp.StatusCode)
	}

	return ParseChecksums(resp.Body)
}
