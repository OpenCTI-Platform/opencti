import { RefObject } from 'react';
import { MarkdownTempAttachmentRegistry } from './markdownImageTempUtils';

type CleanupRefs = {
  pendingCleanupTimeoutRef: RefObject<Map<string, ReturnType<typeof setTimeout>>>;
  latestMarkdownRef: RefObject<string>;
  isFieldFocusedRef: RefObject<boolean>;
  registry: MarkdownTempAttachmentRegistry;
  delayMs: number;
};

const STORAGE_GET_EMBEDDED_PREFIX = '/storage/get/embedded/';
const STORAGE_VIEW_EMBEDDED_PREFIX = '/storage/view/embedded/';
const STORAGE_VIEW_EMBEDDED_PREFIX_ENCODED = '/storage/view/embedded%2F';

const parseMarkdownImageDestination = (destination: string): string | null => {
  let index = 0;
  while (index < destination.length && /\s/.test(destination[index])) {
    index += 1;
  }

  if (index >= destination.length) {
    return null;
  }

  if (destination[index] === '<') {
    const closing = destination.indexOf('>', index + 1);
    if (closing < 0) {
      return null;
    }
    return destination.slice(index + 1, closing);
  }

  const start = index;
  while (index < destination.length && !/\s/.test(destination[index])) {
    index += 1;
  }
  if (index <= start) {
    return null;
  }

  return destination.slice(start, index);
};

// Extracts the storage path (e.g. "embedded/Report/r-1/image.png") from a markdown
// image URL if and only if it points to an embedded file in this platform's storage.
// Three URL forms are supported:
//   1. Relative /storage/get/embedded/...
//   2. Relative /storage/view/embedded/...
//   3. Absolute https://host/storage/view/embedded%2F... (percent-encoded path segment)
// Returns null for any URL that does not match these patterns (external images, etc.).
const extractEmbeddedStoragePathFromUrl = (url: string): string | null => {
  const trimmed = url.trim();
  const decodeEmbeddedEncodedPath = (encodedPath: string): string | null => {
    try {
      return decodeURIComponent(encodedPath).split(/[?#]/)[0];
    } catch {
      return null;
    }
  };
  const startsWithIgnoreCase = (value: string, prefix: string): boolean => value.toLowerCase().startsWith(prefix.toLowerCase());

  const pathCandidate = (() => {
    if (trimmed.startsWith('/')) {
      return trimmed.split(/[?#]/)[0];
    }
    try {
      return new URL(trimmed).pathname;
    } catch {
      return null;
    }
  })();

  if (!pathCandidate) {
    return null;
  }

  if (startsWithIgnoreCase(pathCandidate, STORAGE_GET_EMBEDDED_PREFIX)) {
    return pathCandidate.slice('/storage/get/'.length);
  }

  if (startsWithIgnoreCase(pathCandidate, STORAGE_VIEW_EMBEDDED_PREFIX)) {
    return pathCandidate.slice(STORAGE_VIEW_EMBEDDED_PREFIX.length - 'embedded/'.length);
  }

  if (startsWithIgnoreCase(pathCandidate, STORAGE_VIEW_EMBEDDED_PREFIX_ENCODED)) {
    const encodedPath = pathCandidate.slice('/storage/view/'.length);
    return decodeEmbeddedEncodedPath(encodedPath);
  }

  return null;
};

export const getImageFiles = (files: File[]): File[] => files.filter((file) => file.type.startsWith('image/'));

export const getImageFilesFromDataTransfer = (dataTransfer?: DataTransfer | null): File[] => {
  const files = dataTransfer?.files ? Array.from(dataTransfer.files) : [];
  return getImageFiles(files);
};

export const getImageFilesFromClipboardData = (clipboardData?: DataTransfer | null): File[] => {
  const items = Array.from(clipboardData?.items ?? []);
  return items
    .filter((item) => item.kind === 'file' && item.type.startsWith('image/'))
    .map((item) => item.getAsFile())
    .filter((file): file is File => file !== null);
};

export const clearPendingCleanup = (
  pendingCleanupTimeoutRef: RefObject<Map<string, ReturnType<typeof setTimeout>>>,
  token: string,
) => {
  const timeoutId = pendingCleanupTimeoutRef.current.get(token);
  if (timeoutId) {
    clearTimeout(timeoutId);
    pendingCleanupTimeoutRef.current.delete(token);
  }
};

export const scheduleTokenCleanup = ({
  pendingCleanupTimeoutRef,
  latestMarkdownRef,
  isFieldFocusedRef,
  registry,
  delayMs,
}: CleanupRefs, token: string) => {
  const timeoutId = setTimeout(() => {
    pendingCleanupTimeoutRef.current.delete(token);

    if (latestMarkdownRef.current.includes(token)) {
      return;
    }

    // Keep local temp images alive while user is actively editing so
    // cut/copy/paste and cursor moves do not lose preview rendering.
    if (!isFieldFocusedRef.current) {
      registry.removeTempAttachment(token);
      return;
    }

    if (pendingCleanupTimeoutRef.current.has(token)) {
      return;
    }

    scheduleTokenCleanup({
      pendingCleanupTimeoutRef,
      latestMarkdownRef,
      isFieldFocusedRef,
      registry,
      delayMs,
    }, token);
  }, delayMs);

  pendingCleanupTimeoutRef.current.set(token, timeoutId);
};

export const cleanupRemovedTempAttachments = ({
  pendingCleanupTimeoutRef,
  latestMarkdownRef,
  isFieldFocusedRef,
  registry,
  delayMs,
}: CleanupRefs, markdown: string, immediate = false) => {
  const knownTokens = registry.listTokens();
  for (let i = 0; i < knownTokens.length; i += 1) {
    const token = knownTokens[i];
    if (markdown.includes(token)) {
      clearPendingCleanup(pendingCleanupTimeoutRef, token);
    } else if (immediate) {
      clearPendingCleanup(pendingCleanupTimeoutRef, token);
      registry.removeTempAttachment(token);
    } else if (!pendingCleanupTimeoutRef.current.has(token)) {
      scheduleTokenCleanup({
        pendingCleanupTimeoutRef,
        latestMarkdownRef,
        isFieldFocusedRef,
        registry,
        delayMs,
      }, token);
    }
  }
};

// Finds every embedded image path referenced in a markdown string.
// Looks for the markdown image syntax ![alt](url), extracts the url part,
// then checks if it points to this platform's embedded storage – if so, keeps the path.
// A simple regex is not used because urls can contain parentheses themselves,
// so we count opening/closing parens to locate the correct closing ")" character.
// Results are deduplicated and paths with ".." are dropped to prevent directory traversal.
export const extractEmbeddedStoragePathsFromMarkdown = (markdown: string): string[] => {
  const paths = new Set<string>();
  let cursor = 0;

  while (cursor < markdown.length) {
    const imageStart = markdown.indexOf('![', cursor);
    if (imageStart < 0) {
      break;
    }

    const altEnd = markdown.indexOf(']', imageStart + 2);
    if (altEnd < 0 || markdown[altEnd + 1] !== '(') {
      cursor = imageStart + 2;
      continue;
    }

    const destinationStart = altEnd + 2;
    let index = destinationStart;
    let nestedParentheses = 0;
    while (index < markdown.length) {
      const char = markdown[index];
      if ((char === '\n' || char === '\r') && nestedParentheses === 0) {
        break;
      }
      if (char === '\\') {
        index += 2;
        continue;
      }
      if (char === '(') {
        nestedParentheses += 1;
      } else if (char === ')') {
        if (nestedParentheses === 0) {
          break;
        }
        nestedParentheses -= 1;
      }
      index += 1;
    }

    if (index >= markdown.length || markdown[index] !== ')') {
      cursor = imageStart + 2;
      continue;
    }

    const destination = markdown.slice(destinationStart, index);
    const imageUrl = parseMarkdownImageDestination(destination);
    if (imageUrl) {
      const embeddedPath = extractEmbeddedStoragePathFromUrl(imageUrl);
      if (embeddedPath) {
        const normalized = embeddedPath.trim().replace(/^\/+/, '').split(/[?#]/)[0];
        if (!normalized.includes('..')) {
          paths.add(normalized);
        }
      }
    }

    cursor = index + 1;
  }

  return Array.from(paths);
};
