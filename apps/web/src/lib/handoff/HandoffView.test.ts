/** @vitest-environment jsdom */

/**
 * V20-PR06: verified handoff receiver view — deliberate actions only.
 *
 * Proves the production path invariants:
 * - the payload renders as literal text (no HTML execution),
 * - nothing is copied, saved, or opened automatically on mount,
 * - Copy/Save/Open each fire only from their own click,
 * - Open is hidden for malformed/unsupported links and opens the validated
 *   URL with noopener/noreferrer.
 */

import { mount, tick, unmount } from 'svelte';
import { afterEach, describe, expect, it, vi } from 'vitest';

import HandoffView from './HandoffView.svelte';
import type { TransferOutcome } from '../session/transfer.js';

type Handoff = NonNullable<TransferOutcome['handoff']>;

let root: HTMLElement | null = null;
let component: Record<string, unknown> | null = null;

function render(handoff: Handoff): HTMLElement {
  root = document.createElement('div');
  document.body.appendChild(root);
  component = mount(HandoffView, { target: root, props: { handoff } }) as unknown as Record<
    string,
    unknown
  >;
  return root;
}

afterEach(() => {
  if (component) {
    unmount(component as never);
    component = null;
  }
  root?.remove();
  root = null;
  vi.restoreAllMocks();
});

function buttonNamed(el: HTMLElement, name: string): HTMLButtonElement | null {
  const buttons = [...el.querySelectorAll('button')];
  return (buttons.find((b) => b.textContent?.trim().startsWith(name)) as HTMLButtonElement) ?? null;
}

describe('HandoffView deliberate actions', () => {
  it('renders the payload as literal text, not HTML', async () => {
    const el = render({ contentKind: 'text', text: '<img src=x onerror="alert(1)">hello' });
    await tick();
    expect(el.querySelector('img')).toBeNull();
    expect(el.querySelector('.handoff-body')?.textContent).toContain(
      '<img src=x onerror="alert(1)">hello',
    );
  });

  it('does not touch the clipboard or open anything on mount', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    render({ contentKind: 'link', text: 'https://example.com/x' });
    await tick();
    expect(writeText).not.toHaveBeenCalled();
    expect(open).not.toHaveBeenCalled();
  });

  it('copies only on Copy click', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    const el = render({ contentKind: 'text', text: 'secret note' });
    await tick();
    const copy = buttonNamed(el, 'Copy');
    expect(copy).not.toBeNull();
    await copy!.click();
    await tick();
    expect(writeText).toHaveBeenCalledTimes(1);
    expect(writeText).toHaveBeenCalledWith('secret note');
  });

  it('saves only on Save click', async () => {
    const createObjectURL = vi.fn().mockReturnValue('blob:fake');
    const revokeObjectURL = vi.fn();
    (URL as unknown as { createObjectURL: unknown }).createObjectURL = createObjectURL;
    (URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = revokeObjectURL;
    const clicked: string[] = [];
    const origCreate = document.createElement.bind(document);
    vi.spyOn(document, 'createElement').mockImplementation(((tag: string, ...rest: unknown[]) => {
      const node = origCreate(tag, ...(rest as []));
      if (tag === 'a') {
        (node as HTMLAnchorElement).click = () => {
          clicked.push((node as HTMLAnchorElement).download);
        };
      }
      return node;
    }) as typeof document.createElement);
    const el = render({ contentKind: 'text', text: 'save me' });
    await tick();
    expect(createObjectURL).not.toHaveBeenCalled();
    const save = buttonNamed(el, 'Save');
    expect(save).not.toBeNull();
    await save!.click();
    await tick();
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(clicked).toEqual(['text.txt']);
  });

  it('hides Open for malformed links and never opens them', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    for (const bad of [
      'javascript:alert(1)',
      'ftp://example.com/x',
      'not a url',
      'https://exam ple.com',
    ]) {
      const el = render({ contentKind: 'link', text: bad });
      await tick();
      expect(buttonNamed(el, 'Open'), `Open visible for ${bad}`).toBeNull();
      expect(el.textContent).toContain('cannot be opened');
      if (component) unmount(component as never);
      component = null;
      el.remove();
      root = null;
    }
    expect(open).not.toHaveBeenCalled();
  });

  it('opens a validated https link only on Open click, with noopener/noreferrer', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const el = render({ contentKind: 'link', text: 'https://example.com/path?q=1' });
    await tick();
    const openBtn = buttonNamed(el, 'Open');
    expect(openBtn).not.toBeNull();
    expect(open).not.toHaveBeenCalled();
    await openBtn!.click();
    await tick();
    expect(open).toHaveBeenCalledTimes(1);
    expect(open).toHaveBeenCalledWith(
      'https://example.com/path?q=1',
      '_blank',
      'noopener,noreferrer',
    );
  });
});
