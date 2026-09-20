// Command desktop is the SendBeam desktop app. It runs the shared Go engine
// (packages/engine) behind Wails v3 services and a system-WebView frontend; all
// WebRTC, crypto, file I/O, durability, and trust logic stays in the engine.
//
// Build modes:
//
//	# Desktop (native window; needs platform WebView deps)
//	go build -o sendbeam-desktop .
//
//	# Server (headless HTTP; no GUI deps, used by CI and tests)
//	go build -tags server -o sendbeam-desktop-server .
package main

import (
	"embed"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/icons"

	"github.com/sendbeam/desktop/internal/config"
	"github.com/sendbeam/desktop/internal/engine"
	"github.com/sendbeam/desktop/internal/lifecycle"
	"github.com/sendbeam/engine/receiver"
)

//go:embed all:frontend/dist
var assets embed.FS

// V20-PR07: package-level handles so OS share entry points (second-instance
// forwarding, startup file args, ApplicationOpenedWithFile) can stage paths
// into the send composer once the app is up.
var (
	transferSvc    *engine.TransferService
	sendBeamWindow *application.WebviewWindow
)

func main() {
	// Single-instance lock: ensure only one authoritative desktop process runs
	// to prevent racing on transfer journals, config, or destinations.
	// V20-PR07: the same config dir hosts the forward channel a second
	// instance uses to hand over share paths instead of starting a duplicate.
	configDir := os.TempDir()
	if userCfg, err := os.UserConfigDir(); err == nil {
		configDir = filepath.Join(userCfg, config.AppDirName)
	}
	lockPath := filepath.Join(configDir, "sendbeam.lock")
	lock, err := lifecycle.AcquireSingleInstanceLock(lockPath)
	if err != nil {
		if errors.Is(err, lifecycle.ErrAnotherInstanceRunning) {
			forwardShareArgs(configDir)
		}
		// Fail closed on lock acquisition errors rather than running unprotected
		fmt.Fprintf(os.Stderr, "SendBeam Desktop: single-instance lock failed: %v\n", err)
		os.Exit(1)
	}
	if lock != nil {
		defer func() { _ = lock.Release() }()
	}

	// V20-PR07: forward channel for OS Share / Send to / Open with launches.
	// A second instance forwards its share paths here; they are queued and
	// fed into the send composer once the window and services are ready.
	shareCh := make(chan []string, 16)
	if fwdInfo, fwdLn, ferr := lifecycle.WriteForwardInfo(configDir); ferr != nil {
		log.Printf("SendBeam Desktop: share channel unavailable: %v", ferr)
	} else {
		defer func() {
			_ = fwdLn.Close()
			_ = lifecycle.ClearForwardInfo(configDir)
		}()
		go lifecycle.ServeForward(fwdLn, fwdInfo, func(paths []string) {
			shareCh <- paths
		})
	}

	transferSvc = engine.NewTransferService(
		// Emit every transfer snapshot to the frontend.
		func(name string, data any) {
			if app := application.Get(); app != nil && app.Event != nil {
				app.Event.Emit(name, data)
			}
		},
		// Real signaling server (same wsclient the CLI uses → browser/CLI interop).
		nil,
	)
	transferSvc.SetNotifier(lifecycle.DefaultNotifier())
	transferSvc.SetPicker(wailsPicker{})

	cfg, _ := transferSvc.GetConfig()

	// Lifecycle Coordinator: manages cancellable window closing hooks,
	// system power sleep/wake notifications, and bounded idempotent shutdown.
	lifecycleCoord := lifecycle.NewCoordinator(
		cfg.CloseToTray,
		transferSvc,
		func(kind, phase string) {
			if app := application.Get(); app != nil && app.Event != nil {
				app.Event.Emit(engine.TransferEventName, map[string]any{
					"kind":  kind,
					"phase": phase,
				})
			}
		},
	)

	deviceSvc, err := engine.NewDeviceService(
		func(name string, data any) {
			if app := application.Get(); app != nil && app.Event != nil {
				app.Event.Emit(name, data)
			}
		},
		"",
	)
	if err != nil {
		log.Printf("SendBeam Desktop: device service failed to initialize: %v", err)
	}
	if deviceSvc != nil {
		defer deviceSvc.Close()
		transferSvc.SetDeviceService(deviceSvc)
		if id, err := deviceSvc.GetIdentityManager().GetOrCreateIdentity(); err == nil {
			downloadDir := cfg.DownloadDir
			if downloadDir == "" {
				downloadDir = "."
			}
			serverURL := cfg.ServerURL
			if serverURL == "" {
				serverURL = engine.DefaultServer
			}
			if err := transferSvc.StartNativeReceiver(receiver.Config{
				Server:         serverURL,
				DestDir:        downloadDir,
				AutoAccept:     false,
				RequirePadding: cfg.RequirePadding,
				Private:        cfg.RequirePadding,
				Identity:       id,
				TrustStore:     deviceSvc.GetStore(),
				Secrets:        deviceSvc.GetCredentialStore(),
				Tombstones:     deviceSvc.GetTombstoneStore(),
				Port:           0, // LAN discovery handled by deviceSvc
			}); err != nil {
				log.Printf("SendBeam Desktop: native receiver failed to start: %v", err)
			}
		}
	}

	updateSvc := engine.NewUpdateService(
		func(name string, data any) {
			if app := application.Get(); app != nil && app.Event != nil {
				app.Event.Emit(name, data)
			}
		},
		nil,
	)

	services := []application.Service{
		application.NewService(engine.NewService()),
		application.NewService(transferSvc),
		application.NewService(updateSvc),
	}
	if deviceSvc != nil {
		services = append(services, application.NewService(deviceSvc))
	}

	app := application.New(application.Options{
		Name:        "SendBeam Desktop",
		Description: "Secure, end-to-end-encrypted, peer-to-peer file transfer",
		Services:    services,
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		// Server mode (go build -tags server) serves the same app over HTTP —
		// used by CI and headless smoke tests, with no GUI dependencies.
		Server: application.ServerOptions{
			Host: "localhost",
			Port: 18123,
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})

	winOpts := application.WebviewWindowOptions{
		Title:     "SendBeam Desktop",
		Width:     1040,
		Height:    720,
		MinWidth:  760,
		MinHeight: 520,
		URL:       "/",
		// Drag-and-drop files onto the window; the frontend's drop targets
		// carry data-file-drop-target and the runtime posts the dropped paths
		// to the FilesDropped window event below.
		EnableFileDrop: true,
	}
	if cfg.StartMinimized {
		winOpts.StartState = application.WindowStateMinimised
	}

	sendBeamWindow = app.Window.NewWithOptions(winOpts)

	// System Tray: provides an authoritative reopen and quit mechanism so close-to-tray
	// or start-minimized maintains an easily discoverable and restorable window state.
	systemTray := app.SystemTray.New()
	systemTray.SetTooltip("SendBeam")

	switch runtime.GOOS {
	case "darwin":
		systemTray.SetTemplateIcon(icons.SystrayMacTemplate)
	case "windows":
		systemTray.SetIcon(icons.SystrayLight)
		systemTray.SetDarkModeIcon(icons.SystrayDark)
	default:
		systemTray.SetIcon(icons.SystrayLight)
	}

	trayMenu := app.NewMenu()
	trayMenu.Add("Show SendBeam").OnClick(func(_ *application.Context) {
		sendBeamWindow.Show()
		sendBeamWindow.Focus()
	})
	trayMenu.Add("Quit SendBeam").OnClick(func(_ *application.Context) {
		_ = lifecycleCoord.Shutdown(3 * time.Second)
		app.Quit()
	})
	systemTray.SetMenu(trayMenu)
	systemTray.OnClick(func() {
		sendBeamWindow.Show()
		sendBeamWindow.Focus()
	})

	// macOS dock click reopen hook
	app.Event.OnApplicationEvent(events.Mac.ApplicationShouldHandleReopen, func(_ *application.ApplicationEvent) {
		sendBeamWindow.Show()
		sendBeamWindow.Focus()
	})

	// Wire real system sleep/wake notifications provided by Wails v3
	app.Event.OnApplicationEvent(events.Common.SystemWillSleep, func(_ *application.ApplicationEvent) {
		lifecycleCoord.OnSystemWillSleep()
	})
	app.Event.OnApplicationEvent(events.Common.SystemDidWake, func(_ *application.ApplicationEvent) {
		lifecycleCoord.OnSystemDidWake()
	})

	// Cancellable window closing hook: uses RegisterHook so e.Cancel() properly suppresses window destruction
	// when CloseToTray is active and tray access is known usable.
	sendBeamWindow.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if lifecycleCoord.ShouldHideOnClose() {
			sendBeamWindow.Hide()
			e.Cancel()
		}
	})

	// Forward OS file drops to a new send. Dropped paths are absolute; the
	// engine's source expansion handles files and folders identically. The
	// drop event lets the frontend adopt the new transfer id and show the
	// invite as soon as the engine allocates the room.
	sendBeamWindow.OnWindowEvent(events.Common.WindowFilesDropped, func(e *application.WindowEvent) {
		paths := e.Context().DroppedFiles()
		if len(paths) == 0 {
			return
		}
		// Same share pipeline as OS entry points: staged until the frontend
		// is subscribed, then dropped into the composer.
		shareCh <- paths
	})

	// V20-PR07: share entry points feed the same composer as a drag-and-drop —
	// forwarded paths from a second instance, startup file arguments, and OS
	// "Open with" events (e.g. macOS Finder) all land here. Before the
	// frontend has drained the share inbox (TakeStagedShares) its event
	// subscription is not up yet, so shares are staged; afterwards they drop
	// straight into the composer.
	go func() {
		for paths := range shareCh {
			if transferSvc.ShareUIReady() {
				forwardIntoComposer(paths)
			} else {
				transferSvc.StageSharePaths(paths)
			}
			sendBeamWindow.Show()
			sendBeamWindow.Focus()
		}
	}()
	if paths := lifecycle.SharePathsFromArgs(os.Args); len(paths) > 0 {
		shareCh <- paths
	}
	app.Event.OnApplicationEvent(events.Common.ApplicationOpenedWithFile, func(e *application.ApplicationEvent) {
		if p := e.Context().Filename(); p != "" {
			shareCh <- []string{p}
		}
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}

	// Bounded graceful teardown upon exit: cancel active transfers cleanly
	_ = lifecycleCoord.Shutdown(3 * time.Second)
}

// forwardIntoComposer drops paths into the send composer — the same flow as
// a drag-and-drop onto the window: a send run is created and the frontend
// shows the invite. The transfer service validates the paths; nothing is
// transmitted until the user shares the invite and a recipient joins.
func forwardIntoComposer(paths []string) {
	h, err := transferSvc.Drop(paths)
	if err != nil {
		if a := application.Get(); a != nil && a.Event != nil {
			a.Event.Emit(engine.TransferEventName, map[string]any{
				"kind":  "error",
				"error": err.Error(),
			})
		}
		return
	}
	if a := application.Get(); a != nil && a.Event != nil {
		a.Event.Emit(engine.TransferEventName, map[string]any{
			"kind":  "drop",
			"id":    h.ID,
			"files": paths,
		})
	}
	if w := sendBeamWindow; w != nil {
		w.Show()
		w.Focus()
	}
}

// forwardShareArgs hands this process's share paths to the already-running
// instance and exits. It never starts a second engine.
func forwardShareArgs(configDir string) {
	paths := lifecycle.SharePathsFromArgs(os.Args)
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "SendBeam Desktop: another instance is already running.")
		os.Exit(0)
	}
	info, err := lifecycle.ReadForwardInfo(configDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SendBeam Desktop: another instance is running but its share channel is unavailable: %v\n", err)
		os.Exit(0)
	}
	// The first instance may still be starting its listener; retry dial
	// failures briefly, but not rejections (retrying those cannot help).
	var ferr error
	for i := 0; i < 10; i++ {
		if ferr = lifecycle.ForwardPaths(info, paths); ferr == nil {
			os.Exit(0)
		}
		var opErr *net.OpError
		if !errors.As(ferr, &opErr) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "SendBeam Desktop: could not forward %d path(s) to the running instance: %v\n", len(paths), ferr)
	os.Exit(0)
}

type wailsPicker struct{}

func (wailsPicker) PickFiles() ([]string, error) {
	app := application.Get()
	if app == nil || app.Dialog == nil {
		return nil, errors.New("native dialogs unavailable (server mode); enter paths manually")
	}
	dlg := app.Dialog.OpenFileWithOptions(&application.OpenFileDialogOptions{
		CanChooseFiles:          true,
		CanChooseDirectories:    true,
		AllowsMultipleSelection: true,
		Title:                   "Select files and folders to send",
		Message:                 "Choose one or more files or folders to send securely.",
		ButtonText:              "Select",
	})
	return dlg.PromptForMultipleSelection()
}

func (wailsPicker) PickDestination() (string, error) {
	app := application.Get()
	if app == nil || app.Dialog == nil {
		return "", errors.New("native dialogs unavailable (server mode); enter a destination path manually")
	}
	dlg := app.Dialog.OpenFileWithOptions(&application.OpenFileDialogOptions{
		CanChooseFiles:       false,
		CanChooseDirectories: true,
		Title:                "Choose where to save received files",
		Message:              "Received files are written into this folder.",
		ButtonText:           "Choose",
	})
	return dlg.PromptForSingleSelection()
}
