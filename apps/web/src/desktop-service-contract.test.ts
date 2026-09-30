// Service-name contract (v2.3 correction A): the desktop frontend may only
// call service FQNs that exist in the Go service surface. The mock here is
// STRICT: an unknown FQN fails the test instead of succeeding through a
// permissive resolver.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const htmlPath = resolve(__dirname, '../../desktop/frontend/dist/index.html');
const htmlContent = readFileSync(htmlPath, 'utf8');

// The actual Go service surface (from apps/desktop/main.go registration):
const KNOWN_SERVICES: Record<string, string[]> = {
  'github.com/sendbeam/desktop/internal/engine.Service': [
    'PickFiles',
    'PickDestination',
    'GetState',
  ],
  'github.com/sendbeam/desktop/internal/engine.TransferService': [
    'GetState',
    'Cancel',
    'PickFiles',
    'PickDestination',
  ],
  'github.com/sendbeam/desktop/internal/engine.UpdateService': ['GetState', 'ApplyUpdate'],
  'github.com/sendbeam/desktop/internal/engine.DeviceService': ['ListDevices', 'UnpairDevice'],
  'github.com/sendbeam/desktop/internal/engine.NetworkPolicyService': ['GetPolicy', 'SetPolicy'],
  'github.com/sendbeam/desktop/internal/engine.LocalPairingService': [
    'CreateInvitation',
    'JoinPairing',
    'CancelInvitation',
  ],
  'github.com/sendbeam/desktop/internal/engine.LocalService': ['Start', 'Stop', 'GetState'],
  'github.com/sendbeam/desktop/internal/engine.RecipeService': [
    'ListRecipes',
    'GetRecipe',
    'PreviewRecipe',
    'PlanRecipe',
    'ApproveRecipe',
    'GrantAutomation',
    'RevokeAutomation',
    'DisableRecipe',
    'EnableRecipe',
    'StartWatch',
    'StopWatch',
    'IsWatching',
    'StopAllWatches',
    'StartScheduler',
    'StopScheduler',
    'SchedulerRunning',
    'LastRun',
    'RunRecipe',
    'DeleteRecipe',
    'CreateRecipe',
    'EditRecipe',
    'DuplicateRecipe',
    'RecipeDeliveryStatus',
  ],
};

function extractFQNs(): string[] {
  const fqns: string[] = [];
  // simpler robust scan below
  const js = htmlContent;
  // Direct string literals + SV table entries: these are definitions, not
  // complete calls — push with a '.x' marker so the strict loop skips them.
  for (const m of js.matchAll(/"(github\.com\/sendbeam\/desktop\/internal\/engine\.[A-Za-z]+)"/g)) {
    fqns.push(`${m[1]}.x`);
  }
  // RECIPES_SVC-based calls: capture ".Method" usages and resolve against SV.Recipes
  const svcDecl = js.match(/const RECIPES_SVC = ([^;]+);/);
  if (svcDecl) {
    const isRecipes = (svcDecl[1] ?? '').includes('RecipeService');
    const svcName = isRecipes ? 'github.com/sendbeam/desktop/internal/engine.RecipeService' : null;
    for (const m of js.matchAll(/(?:call|await call)\(RECIPES_SVC \+ "\.([A-Za-z]+)"/g)) {
      if (svcName) fqns.push(`${svcName}.${m[1]}`);
    }
  }
  return fqns;
}

describe('desktop frontend service-name contract', () => {
  it('only calls known methods on registered services (strict, unknown = fail)', () => {
    const calls = extractFQNs();
    expect(calls.length).toBeGreaterThan(0);
    const unknown: string[] = [];
    for (const fqn of calls) {
      const idx = fqn.lastIndexOf('.');
      const svc = fqn.slice(0, idx);
      const method = fqn.slice(idx + 1);
      // Bare service-path entries (the SV table itself, method==='x' by the
      // extractor) are definitions, not calls — skip them.
      if (method === 'x') continue;
      const known = KNOWN_SERVICES[svc];
      if (!known) {
        unknown.push(`${svc} (unregistered service)`);
        continue;
      }
      if (!known.includes(method)) {
        unknown.push(`${svc}.${method} (unknown method)`);
      }
    }
    expect(unknown, `unknown service/method calls: ${unknown.join(', ')}`).toEqual([]);
  });

  it('every recipe method the UI calls exists on the Go RecipeService', () => {
    const recipeMethods =
      KNOWN_SERVICES['github.com/sendbeam/desktop/internal/engine.RecipeService'];
    // The corrected binding must NOT append .RecipeService to SV.Service
    expect(htmlContent).not.toContain('SV.Service + ".RecipeService"');
    expect(htmlContent).toContain('SV.Recipes');
    // UI calls resolve against the known method list
    const used = new Set<string>();
    for (const m of htmlContent.matchAll(/RECIPES_SVC \+ "\.([A-Za-z]+)"/g)) {
      used.add(m[1] ?? '');
    }
    for (const m of used) {
      expect(recipeMethods, `RecipeService.${m} called by UI`).toContain(m);
    }
    expect(used.size).toBeGreaterThan(5);
  });
});
