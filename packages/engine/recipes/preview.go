// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

package recipes

import (
	"fmt"
	"strings"
	"time"
)

// Preview renders a human-readable, secret-free summary of a recipe: what
// may be sent, to whom, when (trigger), under which network/privacy
// policy, within which budgets, and the current automation grant state.
// There are no secret fields in the schema by construction — labels, paths
// and device ids are operational identifiers, not credentials — so the
// preview is safe to show in the composer, CLI and logs. Raw hashes and
// checksums are deliberately omitted; only the recipe id (needed to
// reference the recipe) is shown.
func Preview(r Recipe) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Recipe %q (id %s)\n", r.Name, r.ID)
	fmt.Fprintf(&b, "Status: %s\n", r.Status)
	fmt.Fprintf(&b, "Trigger: %s\n", triggerText(r))
	b.WriteString("Sources:\n")
	for _, s := range r.Sources {
		if s.Recursive {
			fmt.Fprintf(&b, "  - %s (recursive)\n", s.Path)
		} else {
			fmt.Fprintf(&b, "  - %s\n", s.Path)
		}
	}
	b.WriteString("Recipients:\n")
	for _, c := range r.Recipients {
		fmt.Fprintf(&b, "  - %s (%s)\n", c.Label, c.DeviceID)
	}
	if len(r.Include) > 0 {
		fmt.Fprintf(&b, "Include filters: %s\n", strings.Join(r.Include, ", "))
	}
	if len(r.Exclude) > 0 {
		fmt.Fprintf(&b, "Exclude filters: %s\n", strings.Join(r.Exclude, ", "))
	}
	padding := "off"
	if r.RequirePadding {
		padding = "on (strict)"
	}
	fmt.Fprintf(&b, "Network policy: %s; traffic padding: %s\n", effectivePolicyName(r), padding)
	fmt.Fprintf(&b, "Budgets: up to %s and %d files per run; %d concurrent run(s)\n",
		formatBytes(r.Budgets.MaxBytesPerRun), r.Budgets.MaxFilesPerRun, r.Budgets.MaxConcurrentRuns)
	if r.ExpiresAt.IsZero() {
		b.WriteString("Expires: never\n")
	} else {
		fmt.Fprintf(&b, "Expires: %s\n", r.ExpiresAt.UTC().Format(time.RFC3339))
	}
	b.WriteString("Automation grant: " + grantText(r) + "\n")
	return b.String()
}

func triggerText(r Recipe) string {
	switch r.Trigger.Kind {
	case TriggerWatch:
		return "watch (parameters reserved; not active in schema v1)"
	case TriggerSchedule:
		return "schedule (parameters reserved; not active in schema v1)"
	default:
		return r.Trigger.Kind
	}
}

func effectivePolicyName(r Recipe) string {
	if r.NetworkPolicy == "" {
		return "online (default)"
	}
	return r.NetworkPolicy
}

func grantText(r Recipe) string {
	g := r.Grant
	if !g.AutoSend {
		if g.ConsentVersion > 0 {
			return fmt.Sprintf("none — a previous auto-send consent (v%d) was revoked; manual runs only", g.ConsentVersion)
		}
		return "none — manual runs only"
	}
	return fmt.Sprintf("auto-send ENABLED (consent v%d, granted %s)",
		g.ConsentVersion, g.GrantedAt.UTC().Format(time.RFC3339))
}

// formatBytes renders a byte count in human units for the preview.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
