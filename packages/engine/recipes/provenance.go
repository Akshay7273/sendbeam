package recipes

import "github.com/sendbeam/wire"

// Provenance is the routine origin label a dispatch carries (V22-PR06):
// which saved routine produced the transfer and what triggered it. The
// dispatcher builds one per admitted dispatch and passes it through the
// enqueuer, which stamps it on the job and (at dispatch) on the wire
// manifest so the receiver's consent surface can show where the transfer
// came from. It carries no secrets — just labels — and must never be
// treated as a trust signal: the peer's identity is bound by the trust
// store, not by these labels.
type Provenance struct {
	// RoutineID is the saved recipe id (32 lowercase hex).
	RoutineID string
	// RoutineName is the saved recipe name (display label).
	RoutineName string
	// SenderLabel is this device's own label (hostname unless the user
	// configured a device name).
	SenderLabel string
	// Trigger is the dispatch reason.
	Trigger TriggerReason
}

// Wire renders the provenance as the wire manifest's advisory origin
// label. A Provenance always carries all four fields; the wire form is
// validated at the manifest boundary (ValidateManifest).
func (p Provenance) Wire() wire.Provenance {
	return wire.Provenance{
		RoutineID:   p.RoutineID,
		RoutineName: p.RoutineName,
		SenderLabel: p.SenderLabel,
		Trigger:     string(p.Trigger),
	}
}

// Display renders the consent-surface line the receiver shows for a
// routine transfer: "Routine: <name> (trigger: <reason>) from <label>".
// It delegates to the wire form so both spellings render identically.
func (p Provenance) Display() string {
	w := p.Wire()
	return w.Display()
}
