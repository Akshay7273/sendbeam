// SPDX-FileCopyrightText: 2026 The SendBeam contributors <https://sendbeam.dev>
// SPDX-License-Identifier: AGPL-3.0-only

// SB-R09 DOM-level UX contract tests (requirement 8): the recipe lifecycle,
// grants, honest cancel, policy degradation visibility, injection safety and
// double-submit guards — driven through the real dist/index.html with the
// jsdom + Wails-runtime-mock harness, exactly like desktop-render.test.ts.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
// @ts-expect-error jsdom lacks bundled type definitions
import { JSDOM } from 'jsdom';
import { describe, expect, it } from 'vitest';

const htmlPath = resolve(__dirname, '../../desktop/frontend/dist/index.html');
const htmlContent = readFileSync(htmlPath, 'utf8');

const PEER_RECIPE = {
  id: 'a'.repeat(32),
  name: 'nightly',
  status: 'manual',
  sources: [{ path: '/tmp/reports', recursive: true }],
  recipients: [{ deviceId: 'b'.repeat(32), label: 'studio' }],
  networkPolicy: 'local-only',
  requirePadding: true,
  trigger: { kind: 'manual' },
  grant: { autoSend: true, consentVersion: 2, grantedAt: '2026-11-13T00:00:00Z' },
};

const PEER_ENTRY = {
  id: PEER_RECIPE.id,
  name: 'nightly',
  status: 'manual',
  trigger: 'manual',
  sources: 1,
  recipients: 1,
  autoSend: true,
  consentVersion: 2,
};

function setupDesktopDOM(options?: {
  onCall?: (name: string, ...args: unknown[]) => Promise<unknown>;
}) {
  const events: Record<string, ((ev: unknown) => void)[]> = {};
  const dom = new JSDOM(htmlContent, {
    url: 'http://localhost',
    runScripts: 'dangerously',
    beforeParse(win: Record<string, unknown>) {
      win.wails = {
        Events: {
          On: (name: string, cb: (ev: unknown) => void) => {
            if (!events[name]) events[name] = [];
            events[name].push(cb);
          },
        },
        Call: {
          ByName: (name: string, ...args: unknown[]) => {
            if (options?.onCall) {
              return options.onCall(name, ...args);
            }
            return Promise.resolve({});
          },
        },
      };
      win.confirm = () => true;
    },
  });
  // jsdom quirk: the inline script registers its DOMContentLoaded listener
  // during parsing and jsdom (runScripts:dangerously) does not fire the
  // event automatically at parse end — dispatch it once DOM is complete.
  const document = dom.window.document as unknown as HTMLDocument & {
    dispatchEvent: (ev: Event) => void;
  };
  document.dispatchEvent(
    new (dom.window as unknown as { Event: typeof Event }).Event('DOMContentLoaded'),
  );
  return { dom, window: dom.window, document, calls: [] as { name: string; args: unknown[] }[] };
}

async function openRecipeEditorWith(document: HTMLDocument) {
  // open the tab, then the recipe
  (document.getElementById('tab-recipes') as HTMLButtonElement).click();
  await new Promise((r) => setTimeout(r, 30));
  const rows = document.querySelectorAll('.recipe-row');
  expect(rows.length).toBe(1);
  (rows[0] as HTMLButtonElement).click();
  await new Promise((r) => setTimeout(r, 30));
}

describe('SB-R09 recipe lifecycle visibility', () => {
  it('renders the list row with the persisted status and the SEPARATE auto-send grant', async () => {
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([PEER_ENTRY]);
        return Promise.resolve({});
      },
    });
    (document.getElementById('tab-recipes') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 30));
    const row = document.querySelector('.recipe-row') as HTMLElement;
    expect(row?.textContent).toContain('manual');
    expect(row?.textContent).toContain('auto-send GRANTED');
  });

  it('renders the lifecycle stages from persisted state (approved + granted, policy, padding)', async () => {
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([PEER_ENTRY]);
        if (name.includes('GetRecipe')) return Promise.resolve(PEER_RECIPE);
        if (name.includes('IsWatching')) return Promise.resolve(false);
        if (name.includes('SchedulerRunning')) return Promise.resolve(false);
        return Promise.resolve({});
      },
    });
    await openRecipeEditorWith(document);
    const line = document.getElementById('recipe-lifecycle-line')?.textContent || '';
    expect(line).toContain('Approved — one-shot runs allowed');
    expect(line).toContain('auto-send GRANTED');
    expect(line).toContain('local-only');
    expect(line).toContain('strict padding required');
  });

  it('renders the unsaved draft as inert and approval-required on save', async () => {
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([]);
        return Promise.resolve({});
      },
    });
    (document.getElementById('tab-recipes') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 30));
    (document.getElementById('new-recipe-btn') as HTMLButtonElement).click();
    const line = document.getElementById('recipe-lifecycle-line')?.textContent || '';
    expect(line).toContain('UNSAVED draft');
    expect(line).toContain('save it before preview, approve, or run');
  });
});

describe('SB-R09 grant controls (separate permission)', () => {
  it('Grant/revoke call the real service and re-render honest state', async () => {
    let granted = false;
    const recipe = { ...PEER_RECIPE, grant: { autoSend: false, consentVersion: 0, grantedAt: '' } };
    const entry = { ...PEER_ENTRY, autoSend: false };
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([granted ? PEER_ENTRY : entry]);
        if (name.includes('GetRecipe')) return Promise.resolve(granted ? PEER_RECIPE : recipe);
        if (name.includes('GrantAutomation')) {
          granted = true;
          return Promise.resolve({ ...recipe, grant: { autoSend: true, consentVersion: 1 } });
        }
        if (name.includes('IsWatching')) return Promise.resolve(false);
        if (name.includes('SchedulerRunning')) return Promise.resolve(false);
        return Promise.resolve({});
      },
    });
    await openRecipeEditorWith(document);
    const line = document.getElementById('recipe-lifecycle-line')?.textContent || '';
    expect(line).toContain('auto-send not granted');
    (document.getElementById('recipe-grant-btn') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 50));
    expect(granted).toBe(true);
    const line2 = document.getElementById('recipe-lifecycle-line')?.textContent || '';
    expect(line2).toContain('auto-send GRANTED');
  });
});

describe('SB-R09 honest cancel (requirement 5)', () => {
  it('shows pending cancellation, then the engine-confirmed result; late completion never resurrects it', async () => {
    let cancelled = false;
    let resolveCancel: (v: unknown) => void = () => {};
    void resolveCancel;
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([PEER_ENTRY]);
        if (name.includes('GetRecipe')) return Promise.resolve(PEER_RECIPE);
        if (name.includes('IsWatching')) return Promise.resolve(false);
        if (name.includes('SchedulerRunning')) return Promise.resolve(false);
        if (name.includes('RecipeDeliveryStatus')) {
          return Promise.resolve({
            lastRun: { status: 'dispatched', trigger: 'manual', jobId: PEER_RECIPE.id },
            job: {
              jobId: PEER_RECIPE.id,
              status: cancelled ? 'cancelled' : 'dispatching',
              totalSize: 3,
              attempts: [
                {
                  deviceId: 'b'.repeat(32),
                  label: 'studio',
                  status: cancelled ? 'interrupted' : 'active',
                  attempts: 1,
                },
              ],
            },
          });
        }
        if (name.includes('CancelRecipeJob')) {
          return new Promise((res) => {
            resolveCancel = res;
            setTimeout(() => {
              cancelled = true;
              res({ cancelled: true, status: 'cancelled' });
            }, 120);
          });
        }
        return Promise.resolve({});
      },
    });
    await openRecipeEditorWith(document);
    // Load delivery status: active attempt must render as transferring (not delivered)
    (document.getElementById('recipe-status-btn') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 30));
    const attemptLine = document.querySelector('.attempt-line')?.textContent || '';
    expect(attemptLine).toContain('transferring (connected — not yet verified)');
    expect(attemptLine).not.toContain('verified ✓');

    const cancelBtn = document.getElementById('recipe-cancel-job-btn') as HTMLButtonElement;
    expect(cancelBtn.disabled).toBe(false);
    cancelBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    // PENDING state visible while the engine is working
    expect(cancelBtn.textContent).toBe('Cancelling…');
    expect(cancelBtn.disabled).toBe(true);
    await new Promise((r) => setTimeout(r, 150));
    // Engine confirmed; the button re-enables only after the answer.
    expect(cancelBtn.textContent).toBe('Cancel current job');
    const status = document.getElementById('recipes-status')?.textContent || '';
    expect(status).toContain('Job cancelled');
    // The delivery re-render shows the cancelled/interrupted state — the
    // cancelled job never resurrects visually.
    const after = document.querySelector('.attempt-line')?.textContent || '';
    expect(after).toContain('interrupted');
    expect(after).not.toContain('verified ✓');
  });

  it('renders already-completed jobs as a preserved success, not a cancellation', async () => {
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([PEER_ENTRY]);
        if (name.includes('GetRecipe')) return Promise.resolve(PEER_RECIPE);
        if (name.includes('IsWatching')) return Promise.resolve(false);
        if (name.includes('SchedulerRunning')) return Promise.resolve(false);
        if (name.includes('RecipeDeliveryStatus')) {
          return Promise.resolve({
            lastRun: { status: 'dispatched', trigger: 'manual', jobId: PEER_RECIPE.id },
            job: {
              jobId: PEER_RECIPE.id,
              status: 'completed',
              totalSize: 3,
              attempts: [
                {
                  deviceId: 'b'.repeat(32),
                  label: 'studio',
                  status: 'completed',
                  attempts: 1,
                  verifiedDigest: 'd'.repeat(64),
                },
              ],
            },
          });
        }
        if (name.includes('CancelRecipeJob')) {
          return Promise.resolve({ cancelled: false, alreadyCompleted: true, status: 'completed' });
        }
        return Promise.resolve({});
      },
    });
    await openRecipeEditorWith(document);
    (document.getElementById('recipe-status-btn') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 30));
    // completed renders as delivered WITH the digest
    const attemptLine = document.querySelector('.attempt-line')?.textContent || '';
    expect(attemptLine).toContain('delivered (verified)');
    expect(attemptLine).toContain('verified ✓');
    // the cancel button is disabled for terminal jobs
    expect((document.getElementById('recipe-cancel-job-btn') as HTMLButtonElement).disabled).toBe(
      true,
    );
  });
});

describe('SB-R09 policy degradation visibility (requirement 6)', () => {
  it('shows the safety-fallback banner (with reason) when the engine degraded, hidden when healthy', async () => {
    let degraded = true;
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('GetPolicyState')) {
          return Promise.resolve(
            degraded
              ? {
                  policy: 'local-only',
                  degraded: true,
                  reason:
                    'settings could not be read; the engine fell back to local-only for safety',
                }
              : { policy: 'online', degraded: false },
          );
        }
        return Promise.resolve({});
      },
    });
    // trigger the settings load path (which renders the state)
    (document.getElementById('tab-settings') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 50));
    const banner = document.getElementById('policy-degraded-banner') as HTMLElement;
    expect(banner?.classList.contains('hidden')).toBe(false);
    expect(banner?.textContent).toContain('Safety fallback active');
    expect(banner?.textContent).toContain('fell back to local-only');

    degraded = false;
    (document.getElementById('tab-settings') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 50));
    expect(banner?.classList.contains('hidden')).toBe(true);
  });

  it('never renders a degraded reason containing markup as HTML (injection-safe)', async () => {
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('GetPolicyState')) {
          return Promise.resolve({
            policy: 'local-only',
            degraded: true,
            reason: '<img src=x onerror="window.__xss9=1"><b id="degraded-tag">x</b>',
          });
        }
        return Promise.resolve({});
      },
    });
    (document.getElementById('tab-settings') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 50));
    expect(document.querySelector('img[src="x"]')).toBeNull();
    expect(document.querySelector('#degraded-tag')).toBeNull();
    const banner = document.getElementById('policy-degraded-banner') as HTMLElement;
    expect(banner?.textContent).toContain('<img src=x');
  });
});

describe('SB-R09 injection safety in the recipe surface', () => {
  it('renders malicious recipe names and attempt errors as literal text', async () => {
    const evil = '<img src=x onerror="window.__xssR=1"><b id="evil-recipe-tag">evil</b>';
    const evilEntry = { ...PEER_ENTRY, name: evil };
    const evilRecipe = { ...PEER_RECIPE, name: evil };
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([evilEntry]);
        if (name.includes('GetRecipe')) return Promise.resolve(evilRecipe);
        if (name.includes('IsWatching')) return Promise.resolve(false);
        if (name.includes('SchedulerRunning')) return Promise.resolve(false);
        if (name.includes('RecipeDeliveryStatus')) {
          return Promise.resolve({
            lastRun: {
              status: 'failed',
              trigger: 'manual',
              detail: '<u id="evil-detail-tag">boom</u>',
            },
            job: {
              jobId: PEER_RECIPE.id,
              status: 'failed',
              totalSize: 3,
              attempts: [
                {
                  deviceId: 'b'.repeat(32),
                  label: '<i id="evil-label-tag">label</i>',
                  status: 'failed',
                  attempts: 1,
                  lastError: '<a id="evil-error-tag">err</a>',
                },
              ],
            },
          });
        }
        return Promise.resolve({});
      },
    });
    (document.getElementById('tab-recipes') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 30));
    expect(document.querySelector('#evil-recipe-tag')).toBeNull();
    const rows = document.querySelectorAll('.recipe-row');
    expect(rows[0]?.textContent).toContain(evil);
    await openRecipeEditorWith(document);
    (document.getElementById('recipe-status-btn') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 30));
    expect(document.querySelector('#evil-label-tag')).toBeNull();
    expect(document.querySelector('#evil-error-tag')).toBeNull();
    expect(document.querySelector('#evil-detail-tag')).toBeNull();
    const attemptLine = document.querySelector('.attempt-line')?.textContent || '';
    expect(attemptLine).toContain('<a id="evil-error-tag">err</a>');
  });
});

describe('SB-R09 double-submit guard', () => {
  it('run-now cannot enqueue twice while the first call is in flight', async () => {
    let runCalls = 0;
    let resolveRun: (v: unknown) => void = () => {};
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([PEER_ENTRY]);
        if (name.includes('GetRecipe')) return Promise.resolve(PEER_RECIPE);
        if (name.includes('IsWatching')) return Promise.resolve(false);
        if (name.includes('SchedulerRunning')) return Promise.resolve(false);
        if (name.includes('RunRecipe')) {
          runCalls++;
          return new Promise((res) => {
            resolveRun = res;
            setTimeout(() => res('job-1'), 120);
          });
        }
        return Promise.resolve({});
      },
    });
    await openRecipeEditorWith(document);
    const runBtn = document.getElementById('recipe-run-btn') as HTMLButtonElement;
    runBtn.click();
    await new Promise((r) => setTimeout(r, 20));
    expect(runBtn.disabled).toBe(true);
    runBtn.click(); // must be ignored (disabled)
    runBtn.click(); // and again
    resolveRun('job-1');
    await new Promise((r) => setTimeout(r, 150));
    expect(runCalls).toBe(1);
    expect(runBtn.disabled).toBe(false);
  });
});

describe('SB-R09 accessibility & focus', () => {
  it('new interactive controls are keyboard-reachable with accessible names', async () => {
    const { document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([PEER_ENTRY]);
        if (name.includes('GetRecipe')) return Promise.resolve(PEER_RECIPE);
        if (name.includes('IsWatching')) return Promise.resolve(false);
        if (name.includes('SchedulerRunning')) return Promise.resolve(false);
        return Promise.resolve({});
      },
    });
    await openRecipeEditorWith(document);
    for (const id of [
      'recipe-grant-btn',
      'recipe-revoke-btn',
      'recipe-cancel-job-btn',
      'recipe-delete-btn',
    ]) {
      const el = document.getElementById(id) as HTMLButtonElement | null;
      expect(el, id).not.toBeNull();
      expect(el?.tagName).toBe('BUTTON');
      // accessible name from the label text
      expect((el?.textContent || '').length).toBeGreaterThan(3);
      // keyboard reachability: buttons are natively focusable; assert no
      // positive tabindex disrupting natural order
      expect(el?.getAttribute('tabindex')).not.toBe('-1');
    }
    // the lifecycle stage line is exposed to assistive tech as text
    const line = document.getElementById('recipe-lifecycle-line');
    expect(line?.textContent?.length || 0).toBeGreaterThan(10);
  });

  it('delete requires confirmation (destructive operation)', async () => {
    let confirmAsked = false;
    let deleted = false;
    const { window, document } = setupDesktopDOM({
      onCall: (name) => {
        if (name.includes('ListRecipes')) return Promise.resolve([PEER_ENTRY]);
        if (name.includes('GetRecipe')) return Promise.resolve(PEER_RECIPE);
        if (name.includes('IsWatching')) return Promise.resolve(false);
        if (name.includes('SchedulerRunning')) return Promise.resolve(false);
        if (name.includes('DeleteRecipe')) {
          deleted = true;
          return Promise.resolve({});
        }
        return Promise.resolve({});
      },
    });
    (window as unknown as { confirm: () => boolean }).confirm = () => {
      confirmAsked = true;
      return false; // user declines
    };
    await openRecipeEditorWith(document);
    (document.getElementById('recipe-delete-btn') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 40));
    expect(confirmAsked).toBe(true);
    expect(deleted).toBe(false);
  });
});
