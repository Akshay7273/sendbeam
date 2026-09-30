      const SV = {
        Service:  "github.com/sendbeam/desktop/internal/engine.Service",
        Transfer: "github.com/sendbeam/desktop/internal/engine.TransferService",
        Update:   "github.com/sendbeam/desktop/internal/engine.UpdateService",
        Device:   "github.com/sendbeam/desktop/internal/engine.DeviceService",
        NetworkPolicy:
          "github.com/sendbeam/desktop/internal/engine.NetworkPolicyService",
        LocalPairing:
          "github.com/sendbeam/desktop/internal/engine.LocalPairingService",
        Local: "github.com/sendbeam/desktop/internal/engine.LocalService",
      };
      const call = (fqn, ...args) => wails.Call.ByName(fqn, ...args);
      const $ = (id) => document.getElementById(id);

      // Safe literal-text DOM rendering helpers: ensure untrusted strings (paths, errors,
      // identities, update details) never enter the HTML parser.
      function setStatusMessage(el, cls, text, extraText) {
        if (!el) return;
        el.replaceChildren();
        if (cls) {
          const span = document.createElement("span");
          span.className = cls;
          span.textContent = text;
          el.appendChild(span);
        } else {
          el.appendChild(document.createTextNode(text));
        }
        if (extraText) {
          el.appendChild(document.createTextNode(extraText));
        }
      }

      const state = {
        recipes: [],        // V23-PR02: saved handoff recipes (editor)
        recipesLoaded: false,
        recipeDraft: null,
        mode: "send",
        selected: [],
        devices: [],
        send: { id: null },
        recv: { id: null, outPath: null },
        activeDevice: null,
        pendingConsentId: null,
        // V21-PR06: network policy and offline (LAN-only) transfer state.
        policy: "online",
        localListenerAddr: "",
        pendingConsentLocal: false,
        offlineInviteExpiresAt: 0,
        offlineInviteTimer: null,
        // V20-PR06: verified handoff payload held for deliberate Copy/Save/Open.
        handoffText: "",
        handoffKind: "",
        handoffOpenUrl: null,
      };

      function setMode(mode) {
        state.mode = mode;
        ["send", "receive", "devices", "interrupted", "recipes", "settings"].forEach((m) => {
          $("tab-" + m).classList.toggle("active", mode === m);
          $("panel-" + m).classList.toggle("active", mode === m);
        });
        if (mode === "devices") loadDevicesList();
        if (mode === "interrupted") loadDurableList();
        if (mode === "settings") loadSettings();
      }
      $("tab-send").addEventListener("click", () => setMode("send"));
      $("tab-receive").addEventListener("click", () => setMode("receive"));
      $("tab-devices").addEventListener("click", () => setMode("devices"));
      $("tab-interrupted").addEventListener("click", () => setMode("interrupted"));
      $("tab-settings").addEventListener("click", () => setMode("settings"));

      function humanBytes(n) {
        if (n >= 1 << 30) return (n / (1 << 30)).toFixed(2) + " GiB";
        if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MiB";
        if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + " KiB";
        return n + " B";
      }
      function humanRate(bps) {
        if (!bps || bps <= 0) return "calculating…";
        if (bps >= 1 << 20) return (bps / (1 << 20)).toFixed(1) + " MiB/s";
        if (bps >= 1 << 10) return (bps / (1 << 10)).toFixed(1) + " KiB/s";
        return Math.round(bps) + " B/s";
      }

      // SEND
      function renderSelection() {
        const list = $("send-list");
        list.replaceChildren();
        for (const p of state.selected) {
          const li = document.createElement("li");
          li.textContent = p.path;
          const span = document.createElement("span");
          span.textContent = p.size ? humanBytes(p.size) : "";
          li.appendChild(span);
          list.appendChild(li);
        }
        list.classList.toggle("hidden", state.selected.length === 0);
        $("send-sel-status").textContent = state.selected.length ? state.selected.length + " item(s) selected" : "";
        $("start-send").disabled = state.selected.length === 0;
      }
      async function pickSend() {
        const res = await call(SV.Transfer + ".PickFiles");
        if (res && res.error) { $("send-sel-status").textContent = res.error; return; }
        if (res && res.paths && res.paths.length) {
          state.selected = res.paths.map((p) => ({ path: p }));
          renderSelection();
        }
      }
      $("pick-send").addEventListener("click", pickSend);
      $("drop-send").addEventListener("click", pickSend);

      // V20-PR07: a drop (drag-and-drop, OS Share / Send to / Open with,
      // second-instance forwarding) stages the paths into a send run; the
      // composer renders the run and the user still picks the recipient —
      // nothing is transmitted until the invite is shared and joined.
      function handleDropEvent(ev) {
        if (!ev || ev.kind !== "drop" || !ev.id) return;
        if (state.send.id && state.send.id !== ev.id) return;
        state.send.id = ev.id;
        state.selected = (ev.files || []).map((p) => ({ path: p }));
        renderSelection();
        $("send-status").textContent = "Preparing secure channel…";
        $("send-progress-card").classList.remove("hidden");
        $("start-send").disabled = true;
      }

      wails.Events.On("sendbeam:transfer", (ev) => {
        handleDropEvent(ev);
      });

      // V20-PR07: drain shares that arrived before the UI was ready (startup
      // file args, forwarded second-instance launches). This call also marks
      // the share UI ready so later shares drop in live.
      call(SV.Transfer + ".TakeStagedShares").then((paths) => {
        if (!paths || !paths.length) return;
        return call(SV.Transfer + ".Drop", paths).then((h) => {
          if (h && !h.error) {
            handleDropEvent({ kind: "drop", id: h.id, files: paths });
          } else if (h && h.error) {
            $("send-status").textContent = String(h.error);
          }
        });
      }).catch(() => {});

      $("start-send").addEventListener("click", () => {
        if (!state.selected.length) return;
        const paths = state.selected.map((p) => p.path);
        const recipient = $("send-recipient") ? $("send-recipient").value : "code";
        const localOnly = state.policy === "local-only";

        if (localOnly && (!recipient || recipient === "code")) {
          $("send-status").textContent =
            "Local only: invite-code sends are disabled. Choose a paired device.";
          return;
        }

        if (recipient === "broadcast:all") {
          if (localOnly) {
            $("send-status").textContent =
              "Local only: broadcast is disabled. Send to one device at a time.";
            return;
          }
          const devIds = state.devices.filter((d) => !d.revoked).map((d) => d.deviceId);
          if (!devIds.length) {
            $("send-status").textContent = "No trusted devices available for broadcast.";
            return;
          }
          $("send-status").textContent = "Broadcasting to " + devIds.length + " devices…";
          $("start-send").disabled = true;
          call(SV.Transfer + ".BroadcastSend", paths, devIds, "").then((results) => {
            const okCount = (results || []).filter((r) => r.status === "ok").length;
            $("send-status").textContent = "Broadcast finished: " + okCount + "/" + devIds.length + " successful.";
            $("start-send").disabled = false;
          }).catch((err) => {
            $("send-status").textContent = String(err);
            $("start-send").disabled = false;
          });
          return;
        }

        // V21-PR06: local-only device sends take the LAN path — no public
        // signaling, STUN/TURN, or relay at any step.
        // V21-PR07: prefer-local tries the LAN path first with explicit
        // online fallback; anything else goes online directly.
        const preferLocal = state.policy === "prefer-local";
        const sendPromise =
          localOnly && recipient && recipient !== "code"
            ? call(SV.Transfer + ".SendToDeviceLocal", paths, recipient)
            : preferLocal && recipient && recipient !== "code"
              ? call(SV.Transfer + ".SendToDevicePreferLocal", paths, recipient, "")
              : recipient && recipient !== "code"
                ? call(SV.Transfer + ".SendToDevice", paths, recipient, "")
                : call(SV.Transfer + ".Send", paths, "");

        sendPromise.then((h) => {
          if (h && h.error) { $("send-status").textContent = h.error; return; }
          state.send.id = h.id;
          $("send-status").textContent = "Preparing secure channel…";
          $("send-progress-card").classList.remove("hidden");
          $("start-send").disabled = true;
        }).catch((err) => { $("send-status").textContent = String(err); });
      });

      // V20-PR06: encrypted text/link handoff composer — targeted to a paired
      // trusted device only; the backend validates kind, UTF-8, size, and link
      // shape. The payload is verified before the receiver may Copy/Save/Open it.
      const MAX_HANDOFF_BYTES = 262144;
      function handoffCanSend() {
        const kind = $("handoff-kind").value;
        // V20-PR06: text preserves the exact user bytes (only whitespace-only
        // input is rejected); links are trimmed before URL validation. The
        // ceiling is measured in UTF-8 bytes, not JS string length.
        const input = $("handoff-text").value;
        const raw = kind === "link" ? input.trim() : input;
        if (!raw || (kind === "text" && !raw.trim())) return false;
        if (new TextEncoder().encode(raw).length > MAX_HANDOFF_BYTES) return false;
        const recipient = $("send-recipient") ? $("send-recipient").value : "code";
        if (recipient === "code") return false;
        if (kind === "link") {
          if (/\s/.test(raw)) return false;
          try {
            const url = new URL(raw);
            if (url.protocol !== "http:" && url.protocol !== "https:") return false;
            if (!url.hostname) return false;
          } catch {
            return false;
          }
        }
        return true;
      }
      function updateHandoffStart() {
        $("start-handoff").disabled = !handoffCanSend();
      }
      $("handoff-text").addEventListener("input", updateHandoffStart);
      $("handoff-kind").addEventListener("change", updateHandoffStart);
      $("send-recipient").addEventListener("change", updateHandoffStart);
      $("start-handoff").addEventListener("click", () => {
        const kind = $("handoff-kind").value;
        // V20-PR06: send the exact bytes the composer validated (text is
        // untrimmed; links were trimmed during validation).
        const input = $("handoff-text").value;
        const raw = kind === "link" ? input.trim() : input;
        const recipient = $("send-recipient").value;
        $("handoff-status").textContent = "Preparing secure channel…";
        $("start-handoff").disabled = true;
        call(SV.Transfer + ".SendHandoffToDevice", kind, raw, recipient, "").then((h) => {
          if (h && h.error) {
            $("handoff-status").textContent = h.error;
            $("start-handoff").disabled = false;
            return;
          }
          state.send.id = h.id;
          $("handoff-status").textContent = "Handoff sending…";
          $("send-progress-card").classList.remove("hidden");
        }).catch((err) => {
          $("handoff-status").textContent = String(err);
          $("start-handoff").disabled = false;
        });
      });

      // RECEIVE
      function recvCanStart() {
        return !!$("recv-code").value.trim();
      }
      function updateRecvStart() { $("start-recv").disabled = !recvCanStart(); }
      $("recv-code").addEventListener("input", updateRecvStart);
      $("recv-dir").addEventListener("input", updateRecvStart);

      $("pick-dest").addEventListener("click", async () => {
        const res = await call(SV.Transfer + ".PickDestination");
        if (res && res.error) { $("recv-status").textContent = res.error; return; }
        if (res && res.paths && res.paths.length) {
          $("recv-dir").value = res.paths[0];
          updateRecvStart();
        }
      });

      $("start-recv").addEventListener("click", () => {
        const code = $("recv-code").value.trim();
        const dir = $("recv-dir").value.trim();
        call(SV.Transfer + ".Receive", code, dir, "").then((h) => {
          if (h && h.error) { $("recv-status").textContent = h.error; return; }
          state.recv.id = h.id;
          $("recv-status").textContent = "Joining " + code + "…";
          $("recv-progress-card").classList.remove("hidden");
          $("start-recv").disabled = true;
        }).catch((err) => { $("recv-status").textContent = String(err); });
      });

      $("recv-reveal").addEventListener("click", () => {
        if (state.recv.id) {
          call(SV.Transfer + ".RevealCompleted", state.recv.id).catch((e) => {
            $("recv-status-line").textContent = "Reveal failed: " + e;
          });
        }
      });

      // V20-PR06: verified handoff receiver actions. The payload is rendered with
      // literal text only — no HTML execution, no auto-open, no clipboard access
      // outside an explicit click. Open re-validates in the backend before launch.
      function validateHandoffLink(text) {
        const trimmed = String(text || "").trim();
        if (!trimmed || /\s/.test(trimmed)) return null;
        try {
          const url = new URL(trimmed);
          if (url.protocol !== "http:" && url.protocol !== "https:") return null;
          if (!url.hostname) return null;
          return url.toString();
        } catch {
          return null;
        }
      }

      function showRecvHandoff(ev) {
        state.handoffKind = ev.contentKind;
        state.handoffText = String(ev.content || "");
        $("recv-handoff-kind").textContent =
          ev.contentKind === "link" ? "Link (not opened)" : "Text note";
        $("recv-handoff-text").textContent = state.handoffText;
        state.handoffOpenUrl =
          ev.contentKind === "link" ? validateHandoffLink(state.handoffText) : null;
        $("recv-handoff-open").classList.toggle("hidden", !state.handoffOpenUrl);
        $("recv-handoff-card").classList.remove("hidden");
      }

      $("recv-handoff-copy").addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(state.handoffText);
          $("recv-handoff-note").textContent = "Copied to clipboard.";
        } catch (e) {
          $("recv-handoff-note").textContent = "Copy failed — select the text manually.";
        }
      });
      $("recv-handoff-save").addEventListener("click", async () => {
        const res = await call(SV.Transfer + ".PickDestination");
        if (res && res.error) {
          $("recv-handoff-note").textContent = res.error;
          return;
        }
        if (!res || !res.paths || !res.paths.length) return;
        try {
          const saved = await call(
            SV.Transfer + ".SaveHandoffText",
            state.handoffKind,
            state.handoffText,
            res.paths[0],
          );
          $("recv-handoff-note").textContent = "Saved to " + saved;
        } catch (e) {
          $("recv-handoff-note").textContent = "Save failed: " + e;
        }
      });
      $("recv-handoff-open").addEventListener("click", () => {
        if (state.handoffOpenUrl) {
          call(SV.Transfer + ".OpenHandoffLink", state.handoffOpenUrl).catch((e) => {
            $("recv-handoff-note").textContent = "Open failed: " + e;
          });
        }
      });

      // CONTROLS
      function wireControls(prefix) {
        const id = () => state[prefix].id;
        $(prefix + "-pause").addEventListener("click", () => call(SV.Transfer + ".Pause", id()).catch((e) => console.error(e)));
        $(prefix + "-resume").addEventListener("click", () => call(SV.Transfer + ".Resume", id()).catch((e) => console.error(e)));
        $(prefix + "-cancel").addEventListener("click", () => call(SV.Transfer + ".Cancel", id()).catch((e) => console.error(e)));
      }
      wireControls("send");
      wireControls("recv");

      function renderChips(container, ev) {
        if (!container) return;
        container.replaceChildren();
        const add = (cls, text) => {
          const span = document.createElement("span");
          span.className = cls;
          span.textContent = text;
          container.appendChild(span);
        };
        if (ev.phase) add("chip", String(ev.phase).replace(/-/g, " "));
        if (ev.transport) add("chip relay", String(ev.transport));
        if (ev.fingerprint) add("chip auth", "fingerprint " + ev.fingerprint);
        if (ev.paused) add("chip err", "paused");
        if (ev.canceled) add("chip err", "canceled");
        if (ev.failed) add("chip err", "failed");
        if (ev.state) add("chip live", String(ev.state));
      }

      function renderTransfer(ev, prefix) {
        const p = prefix === "send" ? "send" : "recv";
        const id = state[p].id;
        if (ev.id !== id) return;

        renderChips($(p + "-chips"), ev);
        $(p + "-bar").style.width = Math.max(0, Math.min(100, ev.percent || 0)) + "%";
        $(p + "-percent").textContent = (ev.percent || 0) + "% · " + humanBytes(ev.doneBytes || 0) + " / " + humanBytes(ev.totalBytes || 0);

        let file = ev.currentFile || "";
        if (ev.fileSize) file += " (" + humanBytes(ev.fileBytes || 0) + " / " + humanBytes(ev.fileSize) + ")";
        $(p + "-file").textContent = file || "—";

        let rate = humanRate(ev.rateBps);
        if (ev.eta) rate += " · " + ev.eta;
        $(p + "-rate").textContent = rate;

        $(p + "-aggregate").textContent = (ev.filesDone || 0) + " / " + (ev.filesTotal || 0) + " files · " + humanBytes(ev.totalBytes || 0) + " total";
        $(p + "-fingerprint").textContent = ev.fingerprint || "awaiting key confirmation…";

        const paused = !!ev.paused;
        $(p + "-pause").disabled = paused || ev.canceled || ev.failed;
        $(p + "-resume").disabled = !paused || ev.canceled || ev.failed;
        $(p + "-cancel").disabled = ev.canceled || ev.failed;

        const status = p === "recv" ? $("recv-status-line") : $("send-status");
        if (ev.kind === "done") {
          const isHandoff = p === "recv" && (ev.contentKind === "text" || ev.contentKind === "link");
          if (isHandoff) {
            // V20-PR06: the verified handoff payload is held for deliberate
            // Copy/Save/Open — nothing is opened or copied automatically.
            setStatusMessage(
              status,
              "ok",
              "✓ Verified " + (ev.contentKind === "link" ? "link" : "text") + " handoff received.",
            );
            showRecvHandoff(ev);
          } else {
            setStatusMessage(
              status,
              "ok",
              "✓ Verified transfer complete.",
              ev.outPath ? " Saved to " + ev.outPath + "." : null
            );
            $("recv-handoff-card").classList.add("hidden");
          }
          $(p + "-pause").disabled = $(p + "-resume").disabled = $(p + "-cancel").disabled = true;
          if (p === "recv" && (ev.outPath || ev.outDir)) {
            state.recv.outPath = ev.outPath || ev.outDir;
            $("recv-reveal").classList.remove("hidden");
          }
        } else if (ev.kind === "error") {
          setStatusMessage(status, "err", "✗ " + (ev.error || "transfer failed"));
        } else if (ev.kind === "connect") {
          status.textContent = "Secure channel established — transferring…";
        } else if (ev.phase === "waiting") {
          status.textContent = "Waiting for the peer to join…";
        }
      }

      wails.Events.On("sendbeam:transfer", (ev) => {
        if (!ev || !ev.id || !ev.kind) return;
        if (ev.id === state.send.id) renderTransfer(ev, "send");
        if (ev.id === state.recv.id) renderTransfer(ev, "recv");

        if (ev.kind === "invite" && ev.id === state.send.id) {
          $("invite-card").classList.remove("hidden");
          $("invite-code").textContent = ev.code;
          $("invite-link").textContent = ev.link || "";
          if (ev.qr && typeof ev.qr === "string" && (ev.qr.startsWith("data:image/") || ev.qr.startsWith("http://") || ev.qr.startsWith("https://"))) {
            $("invite-qr").src = ev.qr;
          } else {
            $("invite-qr").src = "";
          }
          $("invite-status").textContent = "Share the code or link — the receiver can also scan the QR.";
        }
      });

      $("copy-invite").addEventListener("click", async () => {
        const text = $("invite-code").textContent;
        try {
          await navigator.clipboard.writeText(text);
          $("invite-status").textContent = "Invite code copied.";
        } catch (e) {
          const ta = document.createElement("textarea");
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand("copy"); $("invite-status").textContent = "Invite code copied."; }
          catch (err) { $("invite-status").textContent = "Copy failed — select the code manually."; }
          document.body.removeChild(ta);
        }
      });

      // DEVICES
      function formatStatusBadge(status, revoked) {
        const span = document.createElement("span");
        if (revoked || status === "revoked") {
          span.className = "badge-revoked";
          span.textContent = "Revoked";
        } else if (status === "lan_direct") {
          span.className = "badge-lan";
          span.textContent = "LAN Direct";
        } else if (status === "online") {
          span.className = "badge-online";
          span.textContent = "Online";
        } else {
          span.className = "badge-offline";
          span.textContent = "Offline";
        }
        return span;
      }

      function updateRecipientSelect(devices) {
        const sel = $("send-recipient");
        if (!sel) return;
        const currentVal = sel.value;
        sel.replaceChildren();
        // V21-PR06: in local-only mode there is no invite-code signaling and
        // no broadcast; only direct LAN sends to a paired device.
        const localOnly = state.policy === "local-only";
        if (!localOnly) {
          const defOpt = document.createElement("option");
          defOpt.value = "code";
          defOpt.textContent = "Anyone with invite code / link / QR (Default)";
          sel.appendChild(defOpt);
        }

        const activeDevs = (devices || []).filter((d) => !d.revoked);
        for (const d of activeDevs) {
          const opt = document.createElement("option");
          opt.value = d.deviceId;
          const statusText = d.status === "lan_direct" ? "LAN Direct" : d.status === "online" ? "Online" : "Offline";
          opt.textContent = d.localLabel + " (" + statusText + ")";
          sel.appendChild(opt);
        }

        if (activeDevs.length > 1 && !localOnly) {
          const bOpt = document.createElement("option");
          bOpt.value = "broadcast:all";
          bOpt.textContent = "Broadcast to all trusted devices (" + activeDevs.length + ")";
          sel.appendChild(bOpt);
        }

        sel.value = currentVal || (localOnly ? "" : "code");
        if (sel.selectedIndex === -1) sel.selectedIndex = 0;
      }

      function renderDevicesList(devices) {
        state.devices = devices || [];
        updateRecipientSelect(state.devices);

        const tbody = $("devices-tbody");
        if (!tbody) return;
        tbody.replaceChildren();

        if (!devices || devices.length === 0) {
          $("devices-empty").classList.remove("hidden");
          $("devices-table").classList.add("hidden");
          return;
        }

        $("devices-empty").classList.add("hidden");
        $("devices-table").classList.remove("hidden");

        for (const dev of devices) {
          const tr = document.createElement("tr");

          // Device Name + ID
          const tdDev = document.createElement("td");
          const strong = document.createElement("strong");
          strong.textContent = dev.localLabel;
          tdDev.appendChild(strong);
          const devIdDiv = document.createElement("div");
          devIdDiv.className = "mono small";
          devIdDiv.style.color = "var(--text-muted)";
          devIdDiv.textContent = dev.deviceId;
          tdDev.appendChild(devIdDiv);
          tr.appendChild(tdDev);

          // Fingerprint
          const tdFp = document.createElement("td");
          const fpSpan = document.createElement("span");
          fpSpan.className = "mono small";
          fpSpan.textContent = dev.fingerprint;
          tdFp.appendChild(fpSpan);
          tr.appendChild(tdFp);

          // Status Badge
          const tdStatus = document.createElement("td");
          tdStatus.appendChild(formatStatusBadge(dev.status, dev.revoked));
          tr.appendChild(tdStatus);

          // Auto-Accept
          const tdAuto = document.createElement("td");
          if (dev.policy && dev.policy.autoAccept) {
            tdAuto.textContent = "Yes (" + (dev.policy.autoAcceptDestDir || "") + ")";
          } else {
            tdAuto.textContent = "No";
          }
          tr.appendChild(tdAuto);

          // Last Seen
          const tdSeen = document.createElement("td");
          tdSeen.textContent = dev.lastSeenAt || "Never";
          tr.appendChild(tdSeen);

          // Actions
          const tdActions = document.createElement("td");
          tdActions.style.whiteSpace = "nowrap";

          const btnPolicy = document.createElement("button");
          btnPolicy.className = "ghost small";
          btnPolicy.textContent = "Policy";
          btnPolicy.setAttribute("data-id", dev.deviceId);
          btnPolicy.setAttribute("data-action", "policy");
          btnPolicy.addEventListener("click", () => openPolicyModal(dev));
          tdActions.appendChild(btnPolicy);

          const btnRename = document.createElement("button");
          btnRename.className = "ghost small";
          btnRename.textContent = "Rename";
          btnRename.setAttribute("data-id", dev.deviceId);
          btnRename.setAttribute("data-action", "rename");
          btnRename.addEventListener("click", () => openRenameModal(dev));
          tdActions.appendChild(btnRename);

          if (!dev.revoked) {
            const btnSend = document.createElement("button");
            btnSend.className = "ghost small";
            btnSend.textContent = "Send";
            btnSend.setAttribute("data-id", dev.deviceId);
            btnSend.setAttribute("data-action", "send");
            btnSend.addEventListener("click", () => {
              setMode("send");
              if ($("send-recipient")) $("send-recipient").value = dev.deviceId;
            });
            tdActions.appendChild(btnSend);
          }

          const btnUnpair = document.createElement("button");
          btnUnpair.className = "ghost small danger";
          btnUnpair.textContent = "Unpair";
          btnUnpair.setAttribute("data-id", dev.deviceId);
          btnUnpair.setAttribute("data-action", "unpair");
          btnUnpair.addEventListener("click", () => openUnpairModal(dev));
          tdActions.appendChild(btnUnpair);

          tr.appendChild(tdActions);
          tbody.appendChild(tr);
        }
      }

      async function loadDevicesList() {
        try {
          $("devices-status").textContent = "Loading devices…";
          const list = await call(SV.Device + ".ListTrustedDevices");
          $("devices-status").textContent = "";
          renderDevicesList(list);
        } catch (err) {
          $("devices-status").textContent = "Failed to load devices: " + err;
        }
      }

      wails.Events.On("sendbeam:devices", (devices) => {
        renderDevicesList(devices);
      });

      // MODALS
      function hideAllModals() {
        ["modal-pair", "modal-policy", "modal-rename", "modal-unpair", "modal-consent"].forEach((id) => {
          const m = $(id);
          if (m) m.classList.add("hidden");
        });
      }

      // 1. PAIR MODAL
      let activeOfferCanceller = false;
      function openPairModal() {
        hideAllModals();
        $("modal-pair").classList.remove("hidden");
        setPairMode("offer");
      }
      function closePairModal() {
        $("modal-pair").classList.add("hidden");
        if (activeOfferCanceller) {
          call(SV.Device + ".CancelPairingOffer").catch(() => {});
          activeOfferCanceller = false;
        }
      }
      $("open-pair-btn").addEventListener("click", openPairModal);
      $("pair-modal-close").addEventListener("click", closePairModal);
      $("pair-offer-cancel").addEventListener("click", closePairModal);
      $("pair-join-cancel").addEventListener("click", closePairModal);

      function setPairMode(mode) {
        $("pair-tab-offer").classList.toggle("active", mode === "offer");
        $("pair-tab-join").classList.toggle("active", mode === "join");
        $("pair-offer-view").classList.toggle("hidden", mode !== "offer");
        $("pair-join-view").classList.toggle("hidden", mode !== "join");

        if (mode === "offer") {
          startOfferCeremony();
        } else {
          if (activeOfferCanceller) {
            call(SV.Device + ".CancelPairingOffer").catch(() => {});
            activeOfferCanceller = false;
          }
        }
      }
      $("pair-tab-offer").addEventListener("click", () => setPairMode("offer"));
      $("pair-tab-join").addEventListener("click", () => setPairMode("join"));

      async function startOfferCeremony() {
        activeOfferCanceller = true;
        $("pair-offer-code").textContent = "Allocating pairing room…";
        $("pair-offer-status").textContent = "Waiting for peer to connect…";
        const qrImg = $("pair-offer-qr");
        qrImg.classList.add("hidden");
        qrImg.src = "";

        try {
          const res = await call(SV.Device + ".StartPairingOffer", "", "", false, "");
          if (res && res.code) {
            $("pair-offer-code").textContent = res.code;
            if (res.qr && res.qr.startsWith("data:image/png;base64,")) {
              qrImg.src = res.qr;
              qrImg.classList.remove("hidden");
            }
          }
        } catch (err) {
          $("pair-offer-code").textContent = "Offer failed";
          $("pair-offer-status").textContent = String(err);
        }
      }

      $("pair-join-auto-accept").addEventListener("change", (e) => {
        $("pair-join-dest-container").classList.toggle("hidden", !e.target.checked);
      });
      $("pair-join-browse-dest").addEventListener("click", async () => {
        const res = await call(SV.Transfer + ".PickDestination");
        if (res && res.paths && res.paths.length) {
          $("pair-join-dest-dir").value = res.paths[0];
        }
      });
      $("pair-join-submit").addEventListener("click", async () => {
        const code = $("pair-join-code").value.trim();
        const label = $("pair-join-label").value.trim();
        const autoAccept = $("pair-join-auto-accept").checked;
        const destDir = $("pair-join-dest-dir").value.trim();

        if (!code) {
          $("pair-join-status").textContent = "Invite code is required.";
          return;
        }
        if (autoAccept && !destDir) {
          $("pair-join-status").textContent = "Destination directory required when auto-accept is enabled.";
          return;
        }

        $("pair-join-status").textContent = "Pairing with device…";
        $("pair-join-submit").disabled = true;

        try {
          await call(SV.Device + ".PairDevice", "", code, label, autoAccept, destDir);
          $("pair-join-status").textContent = "Paired successfully!";
          closePairModal();
          loadDevicesList();
        } catch (err) {
          $("pair-join-status").textContent = String(err);
        } finally {
          $("pair-join-submit").disabled = false;
        }
      });

      wails.Events.On("sendbeam:pairing_complete", () => {
        $("pair-offer-status").textContent = "Successfully paired!";
        setTimeout(() => {
          closePairModal();
          loadDevicesList();
        }, 1000);
      });

      wails.Events.On("sendbeam:pairing_failed", (ev) => {
        $("pair-offer-status").textContent = "Pairing failed: " + (ev && ev.error ? ev.error : "unknown error");
      });

      // 2. POLICY MODAL
      function openPolicyModal(dev) {
        hideAllModals();
        state.activeDevice = dev;
        $("modal-policy").classList.remove("hidden");

        const info = $("policy-device-info");
        info.replaceChildren();
        const st = document.createElement("strong");
        st.textContent = dev.localLabel;
        info.appendChild(st);
        info.appendChild(document.createTextNode(" (" + dev.fingerprint + ")"));

        const isAuto = !!(dev.policy && dev.policy.autoAccept);
        $("policy-auto-accept").checked = isAuto;
        $("policy-dest-container").classList.toggle("hidden", !isAuto);
        $("policy-dest-dir").value = (dev.policy && dev.policy.autoAcceptDestDir) || "";
        $("policy-require-padding").checked = !!(dev.policy && (dev.policy.require_padding || dev.policy.requirePadding));
        $("policy-status").textContent = "";
      }
      function closePolicyModal() {
        $("modal-policy").classList.add("hidden");
        state.activeDevice = null;
      }
      $("policy-modal-close").addEventListener("click", closePolicyModal);
      $("policy-cancel-btn").addEventListener("click", closePolicyModal);
      $("policy-auto-accept").addEventListener("change", (e) => {
        $("policy-dest-container").classList.toggle("hidden", !e.target.checked);
      });
      $("policy-browse-dest").addEventListener("click", async () => {
        const res = await call(SV.Transfer + ".PickDestination");
        if (res && res.paths && res.paths.length) {
          $("policy-dest-dir").value = res.paths[0];
        }
      });
      $("policy-save-btn").addEventListener("click", async () => {
        if (!state.activeDevice) return;
        const autoAccept = $("policy-auto-accept").checked;
        const destDir = $("policy-dest-dir").value.trim();
        const requirePadding = $("policy-require-padding").checked;
        if (autoAccept && !destDir) {
          $("policy-status").textContent = "Destination folder required when auto-accept is enabled.";
          return;
        }
        $("policy-status").textContent = "Saving policy…";
        try {
          await call(SV.Device + ".UpdateDevicePolicy", state.activeDevice.deviceId, {
            autoAccept: autoAccept,
            autoAcceptDestDir: destDir,
            require_padding: requirePadding,
          });
          closePolicyModal();
          loadDevicesList();
        } catch (err) {
          $("policy-status").textContent = String(err);
        }
      });


      // 3. RENAME MODAL
      function openRenameModal(dev) {
        hideAllModals();
        state.activeDevice = dev;
        $("modal-rename").classList.remove("hidden");
        $("rename-label-input").value = dev.localLabel;
        $("rename-status").textContent = "";
      }
      function closeRenameModal() {
        $("modal-rename").classList.add("hidden");
        state.activeDevice = null;
      }
      $("rename-modal-close").addEventListener("click", closeRenameModal);
      $("rename-cancel-btn").addEventListener("click", closeRenameModal);
      $("rename-save-btn").addEventListener("click", async () => {
        if (!state.activeDevice) return;
        const newLabel = $("rename-label-input").value.trim();
        if (!newLabel) {
          $("rename-status").textContent = "Name cannot be empty.";
          return;
        }
        $("rename-status").textContent = "Saving…";
        try {
          await call(SV.Device + ".RenameDevice", state.activeDevice.deviceId, newLabel);
          closeRenameModal();
          loadDevicesList();
        } catch (err) {
          $("rename-status").textContent = String(err);
        }
      });

      // 4. UNPAIR MODAL
      function openUnpairModal(dev) {
        hideAllModals();
        state.activeDevice = dev;
        $("modal-unpair").classList.remove("hidden");
        const prompt = $("unpair-device-prompt");
        prompt.replaceChildren();
        prompt.appendChild(document.createTextNode("Are you sure you want to unpair "));
        const st = document.createElement("strong");
        st.textContent = dev.localLabel;
        prompt.appendChild(st);
        prompt.appendChild(document.createTextNode(" (" + dev.fingerprint + ")?"));
        $("unpair-status").textContent = "";
      }
      function closeUnpairModal() {
        $("modal-unpair").classList.add("hidden");
        state.activeDevice = null;
      }
      $("unpair-modal-close").addEventListener("click", closeUnpairModal);
      $("unpair-cancel-btn").addEventListener("click", closeUnpairModal);
      $("unpair-confirm-btn").addEventListener("click", async () => {
        if (!state.activeDevice) return;
        const modeEl = document.querySelector('input[name="unpair-mode"]:checked');
        const purge = modeEl ? modeEl.value === "purge" : false;
        $("unpair-status").textContent = "Unpairing…";
        try {
          await call(SV.Device + ".UnpairDevice", state.activeDevice.deviceId, purge);
          closeUnpairModal();
          loadDevicesList();
        } catch (err) {
          $("unpair-status").textContent = String(err);
        }
      });

      // 5. INCOMING CONSENT MODAL
      function showConsentPrompt(req) {
        if (!req || !req.transferId) return;
        state.pendingConsentId = req.transferId;
        // V21-PR06: the offline listener emits the same consent shape with
        // a local marker; the response routes to the matching service.
        state.pendingConsentLocal = !!req.local;
        // V20-PR06: a handoff envelope is rendered inertly — kind and size only,
        // no destination-folder prompt; the payload appears only after verification.
        const isHandoff = req.contentKind === "text" || req.contentKind === "link";
        $("modal-consent").classList.remove("hidden");
        $("modal-consent").querySelector(".modal-header h3").textContent =
          (req.local ? "Incoming Transfer (local network) — " : "") +
          (isHandoff ? (req.contentKind === "link" ? "Incoming Link" : "Incoming Text")
                     : "Incoming Transfer Request");
        $("consent-device-name").textContent =
          req.peerLabel || req.peerName || req.peerDeviceId || "Trusted Device";
        $("consent-fingerprint").textContent = req.fingerprint || "";
        if (isHandoff) {
          $("consent-files-summary").textContent =
            (req.contentKind === "link" ? "Link" : "Text note") +
            " (" + humanBytes(req.totalSize || 0) + ")";
          $("consent-handoff-note").classList.remove("hidden");
          $("consent-dest-row").classList.add("hidden");
          $("consent-accept-btn").textContent = "Accept & Verify";
        } else {
          const label = req.fileName || "File";
          $("consent-files-summary").textContent = label + " (" + humanBytes(req.totalSize || 0) + ")";
          $("consent-handoff-note").classList.add("hidden");
          $("consent-dest-row").classList.remove("hidden");
          $("consent-dest-dir").value = req.destDir || $("cfg-downdir").value || "";
          $("consent-accept-btn").textContent = "Accept Transfer";
        }
        $("consent-status").textContent = "";
      }
      $("consent-browse-dest").addEventListener("click", async () => {
        const res = await call(SV.Transfer + ".PickDestination");
        if (res && res.paths && res.paths.length) {
          $("consent-dest-dir").value = res.paths[0];
        }
      });
      $("consent-accept-btn").addEventListener("click", async () => {
        if (!state.pendingConsentId) return;
        const destDir = $("consent-dest-dir").value.trim();
        $("consent-status").textContent = "Accepting…";
        // V21-PR06: local incoming transfers answer through the offline
        // listener service, not the online transfer service.
        const svc = state.pendingConsentLocal ? SV.Local + ".RespondLocalConsent" : SV.Transfer + ".RespondConsent";
        try {
          await call(svc, state.pendingConsentId, {
            accepted: true,
            destDir: destDir,
          });
          $("modal-consent").classList.add("hidden");
          state.pendingConsentId = null;
          state.pendingConsentLocal = false;
        } catch (err) {
          $("consent-status").textContent = String(err);
        }
      });
      $("consent-decline-btn").addEventListener("click", async () => {
        if (!state.pendingConsentId) return;
        $("consent-status").textContent = "Declining…";
        const svc = state.pendingConsentLocal ? SV.Local + ".RespondLocalConsent" : SV.Transfer + ".RespondConsent";
        try {
          await call(svc, state.pendingConsentId, {
            accepted: false,
            reason: "Declined by user",
          });
          $("modal-consent").classList.add("hidden");
          state.pendingConsentId = null;
          state.pendingConsentLocal = false;
        } catch (err) {
          $("consent-status").textContent = String(err);
        }
      });

      wails.Events.On("sendbeam:consent", (req) => {
        showConsentPrompt(req);
      });

      // DURABLE / INTERRUPTED
      async function loadDurableList() {
        try {
          const items = await call(SV.Transfer + ".ListInterrupted", "");
          const tbody = $("durable-tbody");
          tbody.replaceChildren();
          if (!items || items.length === 0) {
            $("durable-empty").classList.remove("hidden");
            $("durable-empty").textContent = "No interrupted transfers found.";
            $("durable-table").classList.add("hidden");
            return;
          }
          $("durable-empty").classList.add("hidden");
          $("durable-table").classList.remove("hidden");
          for (const item of items) {
            const tr = document.createElement("tr");

            const tdRole = document.createElement("td");
            const chipRole = document.createElement("span");
            chipRole.className = "chip";
            chipRole.textContent = item.role || "";
            tdRole.appendChild(chipRole);
            tr.appendChild(tdRole);

            const tdId = document.createElement("td");
            tdId.className = "mono";
            const tid = String(item.transferId || "");
            tdId.textContent = tid.length > 8 ? tid.slice(0, 8) + "…" : tid;
            tr.appendChild(tdId);

            const tdFiles = document.createElement("td");
            tdFiles.textContent = String(item.files ?? "");
            tr.appendChild(tdFiles);

            const tdProgress = document.createElement("td");
            tdProgress.textContent =
              humanBytes(item.committedBytes || 0) + " / " + humanBytes(item.totalBytes || 0);
            tr.appendChild(tdProgress);

            const tdStatus = document.createElement("td");
            tdStatus.textContent = String(item.status || "");
            tr.appendChild(tdStatus);

            const tdActions = document.createElement("td");
            const btnInspect = document.createElement("button");
            btnInspect.className = "ghost";
            btnInspect.dataset.action = "inspect";
            btnInspect.dataset.id = String(item.transferId || "");
            btnInspect.textContent = "Inspect";

            const btnDiscard = document.createElement("button");
            btnDiscard.className = "ghost danger";
            btnDiscard.dataset.action = "discard";
            btnDiscard.dataset.id = String(item.transferId || "");
            btnDiscard.textContent = "Discard";

            tdActions.appendChild(btnInspect);
            tdActions.appendChild(document.createTextNode(" "));
            tdActions.appendChild(btnDiscard);
            tr.appendChild(tdActions);

            tbody.appendChild(tr);
          }
        } catch (err) {
          $("durable-empty").classList.remove("hidden");
          $("durable-empty").textContent = "Failed to load transfers: " + err;
        }
      }

      $("durable-tbody").addEventListener("click", async (e) => {
        const btn = e.target.closest("button");
        if (!btn) return;
        const id = btn.dataset.id;
        const action = btn.dataset.action;
        if (action === "discard") {
          try {
            await call(SV.Transfer + ".DiscardInterrupted", id, "");
            $("durable-status").textContent = "Discarded transfer " + id;
            loadDurableList();
          } catch (err) { $("durable-status").textContent = "Discard error: " + err; }
        } else if (action === "inspect") {
          try {
            const ins = await call(SV.Transfer + ".InspectInterrupted", id, "");
            alert("Transfer ID: " + ins.transferId + "\nResumable: " + ins.resumable + "\nProblems: " + (ins.problems ? ins.problems.join(", ") : "none"));
          } catch (err) { $("durable-status").textContent = "Inspect error: " + err; }
        }
      });

      $("refresh-durable").addEventListener("click", loadDurableList);
      $("discard-all-durable").addEventListener("click", async () => {
        if (!confirm("Discard all interrupted transfers and partial files?")) return;
        try {
          await call(SV.Transfer + ".DiscardAllInterrupted", "");
          $("durable-status").textContent = "All interrupted transfers discarded.";
          loadDurableList();
        } catch (err) { $("durable-status").textContent = "Discard all error: " + err; }
      });

      // SETTINGS
      // V21-PR06: apply the network policy across the UI. Local only means
      // the signaling server, STUN/TURN, relay, invite codes, and update
      // checks are off; pairing and transfers stay on the LAN.
      function applyPolicyUI(policy) {
        state.policy = policy || "online";
        const localOnly = state.policy === "local-only";
        const banner = $("policy-banner");
        if (localOnly) {
          banner.classList.remove("hidden");
          // Literal text only: the shipped UI builds this banner from text
          // nodes, never from markup.
          banner.replaceChildren();
          const strong = document.createElement("strong");
          strong.textContent = "Local only: ";
          banner.appendChild(strong);
          banner.appendChild(
            document.createTextNode(
              "transfers and pairing stay on your local network — no " +
                "signaling server, no STUN/TURN, no relay, no invite codes, " +
                "and no update checks. Device-to-device and broadcast sends " +
                "are disabled; choose a paired device."
            )
          );
        } else {
          banner.classList.add("hidden");
          banner.replaceChildren();
        }
        updateRecipientSelect(state.devices);
        // Receive tab: invite codes only work online.
        $("recv-code").disabled = localOnly;
        $("start-recv").disabled = localOnly;
        $("recv-local-note").classList.toggle("hidden", !localOnly);
        if (localOnly) {
          $("recv-status").textContent =
            "Local only: incoming files arrive through the offline listener.";
        }
        // Updates: disabled in local-only by the backend.
        $("check-update-btn").disabled = localOnly;
        if (localOnly) {
          $("update-status-label").textContent =
            "Updates disabled in local-only mode.";
        } else {
          // Restore the live update status when leaving local-only.
          call(SV.Update + ".GetStatus")
            .then((st) => {
              if (st) renderUpdateStatus(st);
            })
            .catch(() => {});
        }
        // Text/link handoffs are not supported offline in this release.
        $("card-handoff").classList.toggle("hidden", localOnly);
      }

      async function refreshListenerUI() {
        try {
          const addr = await call(SV.Local + ".ListenAddr");
          state.localListenerAddr = addr || "";
        } catch (err) {
          state.localListenerAddr = "";
        }
        const running = !!state.localListenerAddr;
        $("local-listener-state").textContent = running
          ? "Running on " + state.localListenerAddr
          : "Stopped";
        $("local-listener-toggle").textContent = running
          ? "Stop listener"
          : "Start listener";
      }

      async function loadSettings() {
        try {
          const cfg = await call(SV.Transfer + ".GetConfig");
          if (cfg) {
            $("cfg-server").value = cfg.serverUrl || "";
            $("cfg-ice").value = (cfg.iceServers || []).join("\n");
            $("cfg-downdir").value = cfg.downloadDir || "";
            $("cfg-auto-accept").checked = false; // Strictly false
            $("cfg-require-padding").checked = !!cfg.requirePadding;
          }
        } catch (err) {
          $("settings-status").textContent = "Load error: " + err;
        }
        try {
          const policy = await call(SV.NetworkPolicy + ".GetPolicy");
          $("cfg-network-policy").value = policy || "online";
          applyPolicyUI(policy || "online");
        } catch (err) {
          $("settings-status").textContent = "Policy load error: " + err;
        }
        await refreshListenerUI();
      }

      $("cfg-pick-dir").addEventListener("click", async () => {
        const res = await call(SV.Transfer + ".PickDestination");
        if (res && res.paths && res.paths.length) {
          $("cfg-downdir").value = res.paths[0];
        }
      });

      $("save-settings").addEventListener("click", async () => {
        const server = $("cfg-server").value.trim();
        const ice = $("cfg-ice").value.split("\n").map((s) => s.trim()).filter(Boolean);
        const downdir = $("cfg-downdir").value.trim();
        const requirePadding = $("cfg-require-padding").checked;
        const cfg = {
          serverUrl: server,
          iceServers: ice,
          downloadDir: downdir,
          autoAccept: false,
          requirePadding: requirePadding,
        };
        try {
          await call(SV.Transfer + ".SaveConfigPatch", cfg);
          // V21-PR06: persist the network policy, re-apply it to the
          // background receiver, and sync the offline listener so a policy
          // change takes effect without an app restart.
          const policy = $("cfg-network-policy").value;
          await call(SV.NetworkPolicy + ".SetPolicy", policy);
          await call(SV.Transfer + ".ApplyNetworkPolicy");
          await syncLocalListener(policy);
          applyPolicyUI(policy);
          setStatusMessage($("settings-status"), "ok", "✓ Settings saved successfully.");
        } catch (err) {
          setStatusMessage($("settings-status"), "err", "✗ " + err);
        }
      });

      // V21-PR06: start the offline listener when the policy is
      // offline-capable, stop it when the policy goes back online.
      async function syncLocalListener(policy) {
        try {
          const addr = await call(SV.Local + ".ListenAddr");
          const running = !!addr;
          const want = policy === "local-only" || policy === "prefer-local";
          if (want && !running) {
            await call(SV.Local + ".Start");
          } else if (!want && running) {
            await call(SV.Local + ".Stop");
          }
        } catch (err) {
          setStatusMessage($("local-listener-status"), "err", "✗ " + err);
        }
        await refreshListenerUI();
      }

      $("local-listener-toggle").addEventListener("click", async () => {
        try {
          if (state.localListenerAddr) {
            await call(SV.Local + ".Stop");
          } else {
            await call(SV.Local + ".Start");
          }
        } catch (err) {
          setStatusMessage($("local-listener-status"), "err", "✗ " + err);
        }
        await refreshListenerUI();
      });

      // V21-PR06: offline (LAN-only) pairing flows.
      $("offline-invite-btn").addEventListener("click", async () => {
        try {
          $("offline-invite-status").textContent = "Creating invitation…";
          const inv = await call(SV.LocalPairing + ".CreateInvitationView");
          $("offline-invite-text").textContent = inv.invitation;
          $("offline-invite-qr").src = inv.qr;
          $("offline-invite-addr").textContent = inv.address;
          $("offline-invite-fp").textContent = inv.fingerprint;
          $("offline-invite-exp").textContent = new Date(inv.expiresAt).toLocaleString();
          $("offline-invite-view").classList.remove("hidden");
          $("offline-invite-status").textContent =
            "Share the invitation text or QR code with the nearby device. It expires automatically.";
          if (state.offlineInviteTimer) clearTimeout(state.offlineInviteTimer);
          const ms = new Date(inv.expiresAt).getTime() - Date.now();
          state.offlineInviteTimer = setTimeout(() => {
            $("offline-invite-status").textContent = "Invitation expired.";
            $("offline-invite-view").classList.add("hidden");
          }, Math.max(ms, 0) + 1000);
        } catch (err) {
          $("offline-invite-status").textContent = String(err);
        }
      });
      $("offline-invite-copy").addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText($("offline-invite-text").textContent);
          $("offline-invite-status").textContent = "Invitation copied.";
        } catch (err) {
          $("offline-invite-status").textContent = "Copy failed: " + err;
        }
      });
      $("offline-invite-cancel").addEventListener("click", async () => {
        try {
          await call(SV.LocalPairing + ".CancelInvitation");
        } catch (err) { /* nothing pending */ }
        if (state.offlineInviteTimer) clearTimeout(state.offlineInviteTimer);
        $("offline-invite-view").classList.add("hidden");
        $("offline-invite-status").textContent = "Invitation cancelled.";
      });
      $("offline-join-btn").addEventListener("click", async () => {
        const invitation = $("offline-join-inv").value.trim();
        const deviceName = $("offline-join-name").value.trim();
        if (!invitation) {
          $("offline-join-status").textContent = "Paste an offline invitation first.";
          return;
        }
        try {
          $("offline-join-status").textContent = "Pairing…";
          const res = await call(SV.LocalPairing + ".JoinInvitation", invitation, deviceName);
          $("offline-join-status").textContent =
            "Paired with " + (res.peerDeviceId || "device") + ". It is now a trusted device.";
          $("offline-join-inv").value = "";
          loadDevicesList();
        } catch (err) {
          $("offline-join-status").textContent = String(err);
        }
      });

      $("reset-settings").addEventListener("click", loadSettings);

      // UPDATES
      let updateDismissed = false;

      function renderUpdateStatus(st) {
        if (!st) return;
        // V21-PR06: the backend skips update checks in local-only mode.
        if (st.state === "skipped_local_only") {
          $("update-status-label").textContent =
            "Updates disabled in local-only mode.";
          $("update-banner").classList.add("hidden");
          return;
        }
        const banner = $("update-banner");
        const bannerText = $("update-banner-text");
        const statusLabel = $("update-status-label");
        const details = $("update-details");
        const notes = $("update-notes");
        const checkBtn = $("check-update-btn");
        const installBtn = $("update-install-btn");
        const channelSelect = $("cfg-update-channel");

        if (st.channel && channelSelect.value !== st.channel) {
          channelSelect.value = st.channel;
        }

        if (st.state === "checking") {
          statusLabel.textContent = "Checking for updates…";
          checkBtn.disabled = true;
        } else {
          checkBtn.disabled = false;
        }

        if (st.state === "available") {
          setStatusMessage(statusLabel, "ok", "✓ Version " + (st.latestVersion || "") + " available");
          if (!updateDismissed) {
            bannerText.textContent = "SendBeam Desktop " + (st.latestVersion || "") + " is available!";
            banner.classList.remove("hidden");
          }
          if (st.releaseNotes) {
            notes.textContent = st.releaseNotes;
            details.classList.remove("hidden");
          }
          installBtn.disabled = false;
          installBtn.textContent = "Install Update";
        } else if (st.state === "downloading") {
          statusLabel.textContent = "Downloading and verifying update…";
          bannerText.textContent = "Downloading update " + (st.latestVersion || "") + "…";
          banner.classList.remove("hidden");
          installBtn.disabled = true;
          installBtn.textContent = "Downloading…";
        } else if (st.state === "ready_to_restart") {
          setStatusMessage(statusLabel, "ok", "✓ Update installed! Restart to apply.");
          bannerText.textContent = "Update ready! Restart SendBeam to apply.";
          $("update-banner-apply").textContent = "Restart now";
          banner.classList.remove("hidden");
          installBtn.disabled = true;
          installBtn.textContent = "Restart required";
        } else if (st.state === "managed_by_pkg_manager") {
          statusLabel.replaceChildren();
          const mutedSpan = document.createElement("span");
          mutedSpan.style.color = "var(--text-muted)";
          mutedSpan.textContent = st.message || "Managed by package manager.";
          statusLabel.appendChild(mutedSpan);
          banner.classList.add("hidden");
          details.classList.add("hidden");
        } else if (st.state === "up_to_date") {
          statusLabel.textContent = st.message || "SendBeam Desktop is up to date.";
          banner.classList.add("hidden");
          details.classList.add("hidden");
        } else if (st.state === "error") {
          setStatusMessage(statusLabel, "err", "✗ " + (st.error || "Update check failed"));
          details.classList.add("hidden");
        }
      }

      wails.Events.On("sendbeam:update", (ev) => {
        renderUpdateStatus(ev);
      });

      $("check-update-btn").addEventListener("click", async () => {
        const ch = $("cfg-update-channel").value;
        try {
          const st = await call(SV.Update + ".CheckUpdate", ch);
          renderUpdateStatus(st);
        } catch (e) {
          setStatusMessage($("update-status-label"), "err", "✗ " + e);
        }
      });

      $("cfg-update-channel").addEventListener("change", async () => {
        const ch = $("cfg-update-channel").value;
        try {
          await call(SV.Update + ".SetChannel", ch);
          const st = await call(SV.Update + ".CheckUpdate", ch);
          renderUpdateStatus(st);
        } catch (e) {
          console.error(e);
        }
      });

      async function triggerApply() {
        try {
          const st = await call(SV.Update + ".ApplyUpdate");
          renderUpdateStatus(st);
        } catch (e) {
          setStatusMessage($("update-status-label"), "err", "✗ " + e);
        }
      }

      $("update-banner-apply").addEventListener("click", triggerApply);
      $("update-install-btn").addEventListener("click", triggerApply);
      $("update-banner-dismiss").addEventListener("click", () => {
        updateDismissed = true;
        $("update-banner").classList.add("hidden");
      });

      (async () => {
        try {
          const info = await call(SV.Service + ".Info");
          document.title = "SendBeam Desktop — " + (info.engineVer ? "engine " + info.engineVer : "linked");
        } catch (err) {}

        try {
          const st = await call(SV.Update + ".GetStatus");
          if (st) renderUpdateStatus(st);
        } catch (err) {}

        try {
          await loadDevicesList();
        } catch (err) {}

        try {
          // V21-PR06: apply the persisted network policy at startup so the
          // send/receive/update UI matches it before Settings is ever opened.
          const policy = await call(SV.NetworkPolicy + ".GetPolicy");
          applyPolicyUI(policy || "online");
        } catch (err) {}

        try {
          const consents = await call(SV.Transfer + ".PendingConsents");
          if (consents && consents.length) showConsentPrompt(consents[0]);
        } catch (err) {}

        try {
          // V21-PR06: surface any local incoming transfers already waiting.
          const localConsents = await call(SV.Local + ".PendingLocalConsents");
          if (localConsents && localConsents.length) showConsentPrompt(localConsents[0]);
        } catch (err) {}
      })();

      // ======================================================================
      // V23-PR02: saved handoff recipes — editor + list over RecipeService.
      // New/edited recipes surface their literal errors; a material scope
      // change drops the recipe back to approval-required (the backend
      // re-hashes scope on save and resets the grant).
      // ======================================================================
      const RECIPES_SVC = SV.Service + ".RecipeService";

      async function refreshRecipes() {
        try {
          state.recipes = (await call(RECIPES_SVC + ".ListRecipes")) || [];
          state.recipesLoaded = true;
          renderRecipeList();
        } catch (e) {
          setLiteral($("recipes-status"), "err", "Failed to load recipes: " + e);
        }
      }

      function renderRecipeList() {
        const list = $("recipes-list");
        if (!list) return;
        list.replaceChildren();
        if (!state.recipes.length) {
          const empty = document.createElement("div");
          empty.className = "muted";
          empty.textContent = "No saved handoffs yet. Create one with New handoff.";
          list.appendChild(empty);
          return;
        }
        for (const entry of state.recipes) {
          const row = document.createElement("button");
          row.className = "recipe-row" + (state.recipeDraft && state.recipeDraft.id === entry.id ? " selected" : "");
          row.textContent = `${entry.name} · ${entry.trigger} · ${entry.status}`;
          row.addEventListener("click", () => openRecipeEditor(entry.id));
          list.appendChild(row);
        }
      }

      async function openRecipeEditor(id) {
        try {
          const r = await call(RECIPES_SVC + ".GetRecipe", id);
          state.recipeDraft = {
            id: r.id,
            name: r.name,
            sources: (r.sources || []).map((s) => ({ path: s.path, recursive: !!s.recursive })),
            recipientIds: (r.recipients || []).map((x) => x.deviceId),
            policy: r.networkPolicy || "online",
            padding: !!r.requirePadding,
            triggerKind: (r.trigger && r.trigger.kind) || "manual",
            scheduleParams: (r.trigger && r.trigger.schedule) || null,
            watchParams: (r.trigger && r.trigger.watch) || null,
          };
          renderRecipeEditor();
        } catch (e) {
          setLiteral($("recipes-status"), "err", "Failed to open recipe: " + e);
        }
      }

      function newRecipeDraft() {
        state.recipeDraft = { id: "", name: "", sources: [], recipientIds: [], policy: "online", padding: false, triggerKind: "manual", scheduleParams: null, watchParams: null };
        renderRecipeEditor();
      }

      function draftUpsert() {
        const d = state.recipeDraft || {};
        return {
          id: d.id || "",
          name: $("recipe-name").value.trim(),
          sources: d.sources,
          recipientDeviceIDs: d.recipientIds,
          networkPolicy: $("recipe-policy").value,
          requirePadding: $("recipe-padding").checked,
          triggerKind: $("recipe-trigger").value,
          scheduleParams: $("recipe-trigger").value === "schedule" ? parseScheduleForm() : null,
        };
      }

      function parseScheduleForm() {
        const at = $("recipe-sched-time").value;   // HH:MM
        const tz = $("recipe-sched-tz").value.trim() || "UTC";
        const intervalM = parseInt($("recipe-sched-interval").value, 10);
        if (at) return { kind: "daily", at, tz };
        if (intervalM > 0) return { kind: "interval", everyMinutes: intervalM };
        return null;
      }

      async function saveRecipeDraft() {
        const btn = $("recipe-save");
        try {
          btn.disabled = true;
          const payload = draftUpsert();
          const saved = state.recipeDraft.id
            ? await call(RECIPES_SVC + ".EditRecipe", state.recipeDraft.id, payload)
            : await call(RECIPES_SVC + ".CreateRecipe", payload);
          state.recipeDraft.id = saved.id;
          setLiteral($("recipes-status"), "ok",
            `Saved "${saved.name}" — status ${saved.status}. It stays inert until approved/previewed.`);
          await refreshRecipes();
        } catch (e) {
          setLiteral($("recipes-status"), "err", "Save failed: " + e);
        } finally {
          btn.disabled = false;
        }
      }

      // V23-PR03: preview → approve → run — real service calls, real
      // handlers, separate consent surfaces. Preview/plan have no transfer
      // effects (engine contract); approve moves approval-required → manual
      // (the click IS the approval; it never grants auto-send); run
      // enqueues an ordinary production outbox job and the transfer-center
      // owns delivery. Approve/Run require an explicit save first: the
      // draft cannot run un-persisted.
      let lastPreviewText = "";

      async function previewRecipeDraft() {
        const target = state.recipeDraft && state.recipeDraft.id;
        if (!target) {
          setLiteral($("recipes-status"), "err", "Save the handoff first — preview runs on the stored recipe.");
          return;
        }
        try {
          lastPreviewText = await call(RECIPES_SVC + ".PreviewRecipe", target);
          const plan = await call(RECIPES_SVC + ".PlanRecipe", target);
          renderPreview(lastPreviewText, plan);
          const r = await call(RECIPES_SVC + ".GetRecipe", target);
          setLiteral($("recipes-status"), "ok", `Previewed "${r.name}" — nothing was sent, no jobs created.`);
        } catch (e) {
          setLiteral($("recipes-status"), "err", "Preview failed: " + e);
        }
      }

      function renderPreview(text, planJson) {
        const pane = $("recipe-preview");
        if (!pane) return;
        pane.replaceChildren();
        const pre = document.createElement("pre");
        pre.textContent = text + "\n--- plan ---\n" + planJson;
        pane.appendChild(pre);
        pane.style.display = "";
      }

      async function approveRecipeDraft() {
        const target = state.recipeDraft && state.recipeDraft.id;
        if (!target) {
          setLiteral($("recipes-status"), "err", "Save first, then approve.");
          return;
        }
        try {
          const r = await call(RECIPES_SVC + ".ApproveRecipe", target);
          setLiteral($("recipes-status"), "ok", `Approved "${r.name}" — one-shot runs allowed. Automation still needs its own grant.`);
          await refreshRecipes();
        } catch (e) {
          setLiteral($("recipes-status"), "err", "Approve failed: " + e);
        }
      }

      async function runRecipeDraft() {
        const target = state.recipeDraft && state.recipeDraft.id;
        if (!target) {
          setLiteral($("recipes-status"), "err", "Save first, then run.");
          return;
        }
        try {
          const jobId = await call(RECIPES_SVC + ".RunRecipe", target);
          setLiteral($("recipes-status"), "ok", `Run enqueued: job ${jobId}. Delivery status appears in Interrupted/Transfer center.`);
        } catch (e) {
          setLiteral($("recipes-status"), "err", "Run refused: " + e);
        }
      }

      async function duplicateRecipeDraft() {
        try {
          if (!state.recipeDraft || !state.recipeDraft.id) return;
          const name = ($("recipe-name").value.trim() || "copy") + " (copy)";
          const dup = await call(RECIPES_SVC + ".DuplicateRecipe", state.recipeDraft.id, name);
          setLiteral($("recipes-status"), "ok", `Duplicated as "${dup.name}" (${dup.status}).`);
          await refreshRecipes();
          await openRecipeEditor(dup.id);
        } catch (e) {
          setLiteral($("recipes-status"), "err", "Duplicate failed: " + e);
        }
      }

      function setLiteral(el, cls, text) {
        if (!el) return;
        el.replaceChildren();
        const span = document.createElement("span");
        span.className = cls;
        span.textContent = text;
        el.appendChild(span);
      }

      function renderRecipeEditor() {
        const ed = $("recipe-editor");
        if (!ed) return;
        const d = state.recipeDraft || {};
        $("recipe-name").value = d.name || "";
        $("recipe-policy").value = d.policy || "online";
        $("recipe-padding").checked = !!d.padding;
        $("recipe-trigger").value = d.triggerKind || "manual";
        toggleScheduleRows();
        const src = $("recipe-sources");
        src.replaceChildren();
        for (const s of d.sources || []) {
          const row = document.createElement("div");
          row.className = "recipe-source-row";
          const label = document.createElement("code");
          label.textContent = s.path + (s.recursive ? " (recursive)" : "");
          row.appendChild(label);
          const rm = document.createElement("button");
          rm.textContent = "Remove";
          rm.addEventListener("click", () => {
            state.recipeDraft.sources = state.recipeDraft.sources.filter((x) => x.path !== s.path);
            renderRecipeEditor();
          });
          row.appendChild(rm);
          src.appendChild(row);
        }
        const rec = $("recipe-recipients");
        rec.replaceChildren();
        for (const id of d.recipientIds || []) {
          const chip = document.createElement("code");
          chip.textContent = id.slice(0, 18) + "…";
          rec.appendChild(chip);
        }
        $("recipe-status-line").textContent = d.id ? `Editing ${d.id.slice(0, 10)}…` : "New handoff (starts approval-required)";
      }

      function toggleScheduleRows() {
        const kind = $("recipe-trigger").value;
        $("recipe-schedule-rows").style.display = kind === "schedule" ? "" : "none";
      }

      function wireRecipeUI() {
        $("new-recipe-btn").addEventListener("click", newRecipeDraft);
        $("recipe-save").addEventListener("click", saveRecipeDraft);
        $("recipe-dup").addEventListener("click", duplicateRecipeDraft);
        $("recipe-preview-btn").addEventListener("click", previewRecipeDraft);
        $("recipe-approve-btn").addEventListener("click", approveRecipeDraft);
        $("recipe-run-btn").addEventListener("click", runRecipeDraft);
        $("add-source-btn").addEventListener("click", async () => {
          if (!state.recipeDraft) state.recipeDraft = { id: "", sources: [] };
          if (!state.recipeDraft.sources) state.recipeDraft.sources = [];
          try {
            const picked = await call(SV.Service + ".PickFiles");
            for (const p of picked || []) {
              state.recipeDraft.sources.push({ path: p, recursive: $("recipe-recursive").checked });
            }
            renderRecipeEditor();
          } catch (e) {
            setLiteral($("recipes-status"), "err", "Source pick failed: " + e);
          }
        });
        $("recipe-trigger").addEventListener("change", toggleScheduleRows);
        $("tab-recipes").addEventListener("click", async () => {
          setMode("recipes");
          await refreshRecipes();
        });
      }

      document.addEventListener("DOMContentLoaded", () => {
        if ($("tab-recipes")) wireRecipeUI();
      });
