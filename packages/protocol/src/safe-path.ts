import { FrameType, type FileEntry, type Manifest, type Provenance } from './transfer.js';

export const MAX_TRANSFER_FILES = 4096;
export const MAX_TRANSFER_PATH_BYTES = 1024;
export const MAX_TRANSFER_PATH_DEPTH = 32;
export const MAX_TRANSFER_SEGMENT_BYTES = 255;
export const MAX_MANIFEST_BLOCK_BYTES = 16 * 1024 * 1024;

/** V20-PR06: handoff content kinds for encrypted text/link transfers. */
export const CONTENT_KIND_TEXT = 'text';
export const CONTENT_KIND_LINK = 'link';

/** V20-PR06: caps a single text/link handoff payload; mirrored from Go wire.MaxHandoffBytes. */
export const MAX_HANDOFF_BYTES = 256 * 1024;

/** V20-PR06: reports whether kind is a known handoff content kind. */
export function isHandoffKind(kind: string | undefined): kind is 'text' | 'link' {
  return kind === CONTENT_KIND_TEXT || kind === CONTENT_KIND_LINK;
}

/**
 * V22-PR06: bounds the display labels a manifest provenance may carry —
 * long enough for any sane routine/device name, short enough that a
 * malicious peer cannot bloat the consent surface. Mirrors Go
 * wire.maxProvenanceLabelLen.
 */
export const MAX_PROVENANCE_LABEL_CHARS = 256;

/** V22-PR06: the dispatch reasons a manifest provenance may name. */
export const VALID_PROVENANCE_TRIGGERS = ['manual', 'watch', 'schedule', 'retry'] as const;

const isLowerHex = (s: string, n: number): boolean => s.length === n && /^[0-9a-f]+$/.test(s);

/**
 * V22-PR06: validates a manifest provenance for shape — the routine id
 * must be 32 lowercase hex, the labels non-empty within the label
 * ceiling, and the trigger a known dispatch reason. An absent provenance
 * is valid (an ordinary one-off send). Mirrors Go wire.ValidateProvenance.
 */
export function validateProvenance(provenance: Provenance | undefined): void {
  if (provenance === undefined) return;
  if (!isLowerHex(provenance.routineId, 32)) {
    throw new Error('manifest provenance has an invalid routineId');
  }
  for (const [label, value] of [
    ['routineName', provenance.routineName],
    ['senderLabel', provenance.senderLabel],
  ] as const) {
    if (value === '') throw new Error(`manifest provenance has an empty ${label}`);
    if ([...value].length > MAX_PROVENANCE_LABEL_CHARS) {
      throw new Error(
        `manifest provenance ${label} exceeds the ${MAX_PROVENANCE_LABEL_CHARS}-character ceiling`,
      );
    }
  }
  if (!VALID_PROVENANCE_TRIGGERS.includes(provenance.trigger)) {
    throw new Error(
      `manifest provenance has an unknown trigger ${JSON.stringify(provenance.trigger)}`,
    );
  }
}

const utf8 = new TextEncoder();
const windowsReserved = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;
const unsafeWindowsChars = /[<>:"|?*]/;

/** Canonicalize an untrusted manifest path or throw before any destination is opened. */
export function normalizeTransferPath(input: string): string {
  if (input.length === 0) throw new Error('manifest path is empty');
  if (input.startsWith('/') || input.startsWith('\\') || /^[A-Za-z]:/.test(input)) {
    throw new Error('manifest path must be relative');
  }
  const canonical = input.replaceAll('\\', '/');
  const segments = canonical.split('/');
  if (segments.length > MAX_TRANSFER_PATH_DEPTH) throw new Error('manifest path is too deep');
  for (const segment of segments) {
    if (segment.length === 0 || segment === '.' || segment === '..') {
      throw new Error('manifest path contains an unsafe segment');
    }
    for (const character of segment) {
      if ((character.codePointAt(0) ?? 0) <= 0x1f || unsafeWindowsChars.test(character)) {
        throw new Error('manifest path contains unsafe characters');
      }
    }
    if (segment.endsWith('.') || segment.endsWith(' ')) {
      throw new Error('manifest path has an unsafe suffix');
    }
    if (windowsReserved.test(segment)) throw new Error('manifest path uses a reserved name');
    if (utf8.encode(segment).length > MAX_TRANSFER_SEGMENT_BYTES) {
      throw new Error('manifest path segment is too long');
    }
  }
  if (utf8.encode(canonical).length > MAX_TRANSFER_PATH_BYTES) {
    throw new Error('manifest path is too long');
  }
  return canonical;
}

/** Validate manifest-wide geometry and return a copy with canonical relative paths. */
export function validateManifest(manifest: Manifest): Manifest {
  // V20-PR06: the content-kind envelope is validated first so a forged or future
  // kind can never pass as an ordinary file set.
  if (manifest.contentKind !== undefined && !isHandoffKind(manifest.contentKind)) {
    throw new Error('manifest has an unknown contentKind');
  }
  // V22-PR06: the provenance origin label is validated so a malformed label
  // can never pass as a routine transfer. An absent provenance is an
  // ordinary one-off send.
  validateProvenance(manifest.provenance);
  if (manifest.files.length === 0 || manifest.files.length > MAX_TRANSFER_FILES) {
    throw new Error('manifest has an invalid file count');
  }
  const paths = new Set<string>();
  let totalSize = 0;
  const files: FileEntry[] = manifest.files.map((file, idx) => {
    if (file.idx !== idx) throw new Error('manifest file indexes must be contiguous');
    for (const [label, value] of [
      ['size', file.size],
      ['lastModified', file.lastModified],
      ['blockSize', file.blockSize],
      ['blocks', file.blocks],
    ] as const) {
      if (!Number.isSafeInteger(value)) throw new Error(`manifest ${label} is not a safe integer`);
    }
    if (file.size < 0 || file.lastModified < 0 || file.blockSize <= 0) {
      throw new Error('manifest has invalid file geometry');
    }
    if (file.blockSize > MAX_MANIFEST_BLOCK_BYTES) {
      throw new Error(
        `manifest block size ${file.blockSize} exceeds the ${MAX_MANIFEST_BLOCK_BYTES}-byte ceiling`,
      );
    }
    if (file.blocks !== Math.ceil(file.size / file.blockSize)) {
      throw new Error('manifest has invalid block geometry');
    }
    const name = normalizeTransferPath(file.name);
    const key = name.toLowerCase();
    if (paths.has(key)) throw new Error('manifest contains duplicate paths');
    paths.add(key);
    totalSize += file.size;
    if (!Number.isSafeInteger(totalSize)) throw new Error('manifest total size is too large');
    return { ...file, name };
  });
  if (!Number.isSafeInteger(manifest.totalSize) || manifest.totalSize !== totalSize) {
    throw new Error('manifest total size mismatch');
  }
  // V20-PR06: a handoff envelope must be exactly one small in-memory payload —
  // never a multi-file set and never more than the handoff byte ceiling.
  if (manifest.contentKind !== undefined) {
    if (
      files.length !== 1 ||
      totalSize <= 0 ||
      totalSize > MAX_HANDOFF_BYTES ||
      files[0]!.size !== totalSize
    ) {
      throw new Error(
        `manifest contentKind requires exactly one file of 1 to ${MAX_HANDOFF_BYTES} bytes`,
      );
    }
  }
  return {
    type: FrameType.Manifest,
    ...(manifest.transferId !== undefined ? { transferId: manifest.transferId } : {}),
    ...(manifest.contentKind !== undefined ? { contentKind: manifest.contentKind } : {}),
    // V22-PR06: key order matches the Go struct so the JSON bytes stay identical.
    ...(manifest.provenance !== undefined ? { provenance: manifest.provenance } : {}),
    files,
    totalSize,
  };
}
