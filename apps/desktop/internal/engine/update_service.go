package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/engine/updater"
)

const (
	// UpdateEventName is the Wails event emitted on update status transitions.
	UpdateEventName = "sendbeam:update"

	defaultUpdateRepo = "Akshay7273/sendbeam"
)

// UpdateStatus represents the desktop application update state exposed to the UI.
type UpdateStatus struct {
	State               string `json:"state"` // "idle", "checking", "available", "downloading", "ready_to_restart", "up_to_date", "managed_by_pkg_manager", "error"
	CurrentVersion      string `json:"currentVersion"`
	LatestVersion       string `json:"latestVersion"`
	Channel             string `json:"channel"`
	ReleaseNotes        string `json:"releaseNotes,omitempty"`
	ManagedByPkgManager string `json:"managedByPkgManager,omitempty"`
	NeedsRestart        bool   `json:"needsRestart"`
	Error               string `json:"error,omitempty"`
	Message             string `json:"message"`
}

// UpdateService coordinates desktop application self-updates.
type UpdateService struct {
	emitter     func(name string, data any)
	configStore *config.Store
	updater     *updater.Updater
	status      UpdateStatus
	lastCheck   *updater.CheckResult
	customOpts  []updater.Option
	mu          sync.RWMutex
}

// NewUpdateService creates a new desktop UpdateService.
func NewUpdateService(emitter func(name string, data any), cfgStore *config.Store, opts ...updater.Option) *UpdateService {
	curVer := ProductVersion
	if curVer == "" {
		curVer = "dev"
	}

	initialCh := updater.ChannelStable
	if cfgStore != nil {
		if cfg, err := cfgStore.Load(); err == nil && cfg.UpdateChannel != "" {
			if parsed, err := updater.ParseChannel(cfg.UpdateChannel); err == nil {
				initialCh = parsed
			}
		}
	}

	baseOpts := []updater.Option{
		updater.WithProductKind(updater.ProductKindDesktop),
		updater.WithChannel(initialCh),
	}
	baseOpts = append(baseOpts, opts...)

	u, _ := updater.New(curVer, defaultUpdateRepo, baseOpts...)

	svc := &UpdateService{
		emitter:     emitter,
		configStore: cfgStore,
		updater:     u,
		customOpts:  opts,
		status: UpdateStatus{
			State:          "idle",
			CurrentVersion: curVer,
			Channel:        initialCh.String(),
			Message:        "Ready",
		},
	}

	return svc
}

// GetStatus returns the current update state.
func (s *UpdateService) GetStatus() UpdateStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// SetChannel configures and persists the active update distribution channel.
func (s *UpdateService) SetChannel(channelStr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, err := updater.ParseChannel(channelStr)
	if err != nil {
		return err
	}

	if s.configStore != nil {
		cfg, err := s.configStore.Load()
		if err == nil {
			cfg.UpdateChannel = ch.String()
			_ = s.configStore.Save(cfg)
		}
	}

	curVer := ProductVersion
	if curVer == "" {
		curVer = "dev"
	}

	baseOpts := []updater.Option{
		updater.WithProductKind(updater.ProductKindDesktop),
		updater.WithChannel(ch),
	}
	baseOpts = append(baseOpts, s.customOpts...)

	u, err := updater.New(curVer, defaultUpdateRepo, baseOpts...)
	if err != nil {
		return err
	}

	s.updater = u
	s.status.Channel = ch.String()
	s.emit(s.status)

	return nil
}

// CheckUpdate checks the update server for a newer release on the configured channel.
func (s *UpdateService) CheckUpdate(channelStr string) (UpdateStatus, error) {
	if channelStr != "" {
		if err := s.SetChannel(channelStr); err != nil {
			return s.GetStatus(), err
		}
	}

	s.mu.Lock()
	s.status.State = "checking"
	s.status.Message = fmt.Sprintf("Checking for updates on %s channel…", s.status.Channel)
	s.status.Error = ""
	st := s.status
	s.mu.Unlock()
	s.emit(st)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s.mu.RLock()
	u := s.updater
	s.mu.RUnlock()

	check, err := u.Check(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		s.status.State = "error"
		s.status.Error = err.Error()
		s.status.Message = fmt.Sprintf("Check failed: %v", err)
		s.emit(s.status)
		return s.status, err
	}

	s.lastCheck = check
	s.status.CurrentVersion = check.CurrentVersion.String()
	s.status.Channel = check.Channel.String()

	if check.ManagedByPkgManager != "" {
		s.status.State = "managed_by_pkg_manager"
		s.status.ManagedByPkgManager = check.ManagedByPkgManager
		s.status.Message = check.Message
		s.emit(s.status)
		return s.status, nil
	}

	if !check.UpdateAvailable {
		s.status.State = "up_to_date"
		s.status.LatestVersion = check.LatestVersion.String()
		s.status.Message = check.Message
		s.emit(s.status)
		return s.status, nil
	}

	s.status.State = "available"
	s.status.LatestVersion = check.LatestVersion.String()
	s.status.ReleaseNotes = check.ReleaseNotes
	s.status.Message = fmt.Sprintf("SendBeam Desktop %s is available!", check.LatestVersion)
	s.emit(s.status)

	return s.status, nil
}

// ApplyUpdate downloads, verifies, and stages or applies the update.
func (s *UpdateService) ApplyUpdate() (UpdateStatus, error) {
	s.mu.Lock()
	if s.lastCheck == nil || !s.lastCheck.UpdateAvailable {
		st := s.status
		s.mu.Unlock()
		return st, updater.ErrNoUpdateAvailable
	}

	s.status.State = "downloading"
	s.status.Message = fmt.Sprintf("Downloading and verifying update %s…", s.lastCheck.LatestVersion)
	s.status.Error = ""
	st := s.status
	u := s.updater
	check := s.lastCheck
	s.mu.Unlock()
	s.emit(st)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	err := u.Apply(ctx, check)
	s.mu.Lock()
	defer s.mu.Unlock()

	if err != nil {
		s.status.State = "error"
		s.status.Error = err.Error()
		s.status.Message = fmt.Sprintf("Update failed: %v", err)
		s.emit(s.status)
		return s.status, err
	}

	s.status.State = "ready_to_restart"
	s.status.NeedsRestart = true
	s.status.Message = fmt.Sprintf("Update %s is installed! Restart SendBeam to apply.", check.LatestVersion)
	s.emit(s.status)

	return s.status, nil
}

func (s *UpdateService) emit(st UpdateStatus) {
	if s.emitter != nil {
		s.emitter(UpdateEventName, st)
	}
}
