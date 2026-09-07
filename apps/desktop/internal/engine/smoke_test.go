package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sendbeam/engine/receiver"
	"github.com/sendbeam/engine/trust"
)

func TestNativeArtifactSmoke_BuiltFrontendHTML(t *testing.T) {
	// Locate apps/desktop/frontend/dist/index.html relative to engine test directory
	// In internal/engine: ../../frontend/dist/index.html
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	htmlPath := filepath.Clean(filepath.Join(cwd, "..", "..", "frontend", "dist", "index.html"))
	contentBytes, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("failed to read built frontend HTML asset at %s: %v", htmlPath, err)
	}
	content := string(contentBytes)
	if len(content) == 0 {
		t.Fatalf("built frontend HTML asset is empty at %s", htmlPath)
	}

	// 1. Critical DOM elements for trusted-device handoffs
	requiredIDs := []string{
		`id="tab-devices"`,
		`id="panel-devices"`,
		`id="devices-table"`,
		`id="devices-tbody"`,
		`id="devices-empty"`,
		`id="open-pair-btn"`,
		`id="send-recipient"`,
		`id="modal-pair"`,
		`id="pair-offer-code"`,
		`id="pair-offer-qr"`,
		`id="pair-join-code"`,
		`id="pair-join-submit"`,
		`id="modal-policy"`,
		`id="policy-auto-accept"`,
		`id="policy-require-padding"`,
		`id="policy-dest-dir"`,
		`id="policy-save-btn"`,
		`id="cfg-require-padding"`,
		`id="modal-rename"`,
		`id="rename-label-input"`,
		`id="rename-save-btn"`,
		`id="modal-unpair"`,
		`id="unpair-confirm-btn"`,
		`id="modal-consent"`,
		`id="consent-accept-btn"`,
		`id="consent-decline-btn"`,
	}

	for _, req := range requiredIDs {
		if !strings.Contains(content, req) {
			t.Errorf("built HTML missing required element %s", req)
		}
	}

	// 2. Critical CSS badge classes
	requiredClasses := []string{
		"badge-lan",
		"badge-online",
		"badge-offline",
		"badge-revoked",
		"modal-backdrop",
		"modal-card",
	}

	for _, cls := range requiredClasses {
		if !strings.Contains(content, cls) {
			t.Errorf("built HTML missing required CSS class %s", cls)
		}
	}

	// 3. Security invariant checks: Zero innerHTML / outerHTML / document.write / insertAdjacentHTML
	forbiddenSinks := []string{
		"innerHTML",
		"outerHTML",
		"document.write",
		"insertAdjacentHTML",
		"javascript:",
		"vbscript:",
	}

	for _, sink := range forbiddenSinks {
		if strings.Contains(content, sink) {
			t.Errorf("built HTML violates strict safety invariant, contains forbidden pattern: %q", sink)
		}
	}
}

func TestNativeArtifactSmoke_EngineServicesWiring(t *testing.T) {
	tmpDir := t.TempDir()

	sink := &eventSink{}
	transferSvc := NewTransferService(sink.emit, nil)

	memCreds := trust.NewMemoryCredentialStore()
	deviceSvc, err := NewDeviceServiceWithCredentials(sink.emit, tmpDir, memCreds)
	if err != nil {
		t.Fatalf("NewDeviceServiceWithCredentials failed: %v", err)
	}
	defer deviceSvc.Close()

	// 1. Verify accessors
	if deviceSvc.GetIdentityManager() == nil {
		t.Fatal("expected non-nil IdentityManager")
	}
	if deviceSvc.GetStore() == nil {
		t.Fatal("expected non-nil Store")
	}
	if deviceSvc.GetCredentialStore() == nil {
		t.Fatal("expected non-nil CredentialStore")
	}
	if deviceSvc.GetTombstoneStore() == nil {
		t.Fatal("expected non-nil TombstoneStore")
	}

	// 2. Wire DeviceService into TransferService
	transferSvc.SetDeviceService(deviceSvc)
	if transferSvc.DeviceService() != deviceSvc {
		t.Fatal("expected DeviceService to be wired into TransferService")
	}

	// 3. Retrieve local identity
	localID, err := deviceSvc.GetIdentityManager().GetOrCreateIdentity()
	if err != nil {
		t.Fatalf("GetOrCreateIdentity failed: %v", err)
	}

	// 4. Start Native Receiver using DeviceService identity and stores
	cfg := receiver.Config{
		Server:     DefaultServer,
		DestDir:    tmpDir,
		AutoAccept: false,
		Identity:   localID,
		TrustStore: deviceSvc.GetStore(),
		Secrets:    deviceSvc.GetCredentialStore(),
		Tombstones: deviceSvc.GetTombstoneStore(),
		Port:       0, // disable LAN listener in smoke test
	}

	if err := transferSvc.StartNativeReceiver(cfg); err != nil {
		t.Fatalf("StartNativeReceiver failed: %v", err)
	}

	if transferSvc.NativeReceiver() == nil {
		t.Fatal("expected active NativeReceiver")
	}

	// 5. Query pending consents (should be empty initially)
	consents := transferSvc.PendingConsents()
	if len(consents) != 0 {
		t.Fatalf("expected 0 pending consents, got %d", len(consents))
	}

	// 6. Stop Native Receiver cleanly
	if err := transferSvc.StopNativeReceiver(); err != nil {
		t.Fatalf("StopNativeReceiver failed: %v", err)
	}

	if transferSvc.NativeReceiver() != nil {
		t.Fatal("expected nil NativeReceiver after stop")
	}

	// 7. Verify device listing queries work on clean state
	devs, err := deviceSvc.ListTrustedDevices()
	if err != nil {
		t.Fatalf("ListTrustedDevices failed: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("expected 0 trusted devices initially, got %d", len(devs))
	}
}
