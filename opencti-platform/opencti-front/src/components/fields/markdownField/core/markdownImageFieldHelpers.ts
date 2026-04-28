import { RefObject } from 'react';
import { MarkdownTempAttachmentRegistry } from './markdownImagePreviewUtils';
import { extractMarkdownImageReferences } from './markdownImageParsingUtils';

type CleanupRefs = {
  pendingCleanupTimeoutRef: RefObject<Map<string, ReturnType<typeof setTimeout>>>;
  latestMarkdownRef: RefObject<string>;
  isFieldFocusedRef: RefObject<boolean>;
  registry: MarkdownTempAttachmentRegistry;
  delayMs: number;
};

const EMBEDDED_PATH_PREFIX = 'embedded/';
const STORAGE_VIEW_PREFIX = '/storage/view/';
const STORAGE_VIEW_EMBEDDED_PREFIX = `${STORAGE_VIEW_PREFIX}${EMBEDDED_PATH_PREFIX}`;

const ALLOWED_MARKDOWN_IMAGE_MIME_TYPES = new Set([
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
]);

export type MarkdownImageDragFeedback = 'none' | 'valid' | 'invalid';

// Extracts the storage path (e.g. "embedded/Report/r-1/image.png") from a markdown
// image URL if and only if it points to an embedded file in this platform's storage.
// Two URL forms are supported:
//   1. Relative /storage/view/embedded/...
//   2. Absolute https://host/storage/view/embedded%2F... (percent-encoded path segment)
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

  if (startsWithIgnoreCase(pathCandidate, STORAGE_VIEW_EMBEDDED_PREFIX)) {
    return pathCandidate.slice(STORAGE_VIEW_PREFIX.length);
  }

  if (startsWithIgnoreCase(pathCandidate, STORAGE_VIEW_PREFIX)) {
    const storageViewTail = pathCandidate.slice(STORAGE_VIEW_PREFIX.length);
    const decodedTail = decodeEmbeddedEncodedPath(storageViewTail);
    if (decodedTail && startsWithIgnoreCase(decodedTail, EMBEDDED_PATH_PREFIX)) {
      return decodedTail;
    }
  }

  return null;
};

export const isSvgImageFile = (file: File): boolean => {
  if (file.type.toLowerCase() === 'image/svg+xml') {
    return true;
  }
  return file.name.toLowerCase().endsWith('.svg');
};

export const isAllowedMarkdownImageMimeType = (mimeType: string): boolean => {
  return ALLOWED_MARKDOWN_IMAGE_MIME_TYPES.has(mimeType.toLowerCase());
};

export const getImageFiles = (files: File[]): File[] => {
  return files.filter((file) => {
    const mimeType = file.type.toLowerCase();
    return isAllowedMarkdownImageMimeType(mimeType);
  });
};

export const getMarkdownImageDragFeedback = (dataTransfer?: DataTransfer | null): MarkdownImageDragFeedback => {
  if (!dataTransfer) {
    return 'none';
  }

  const transferTypes = Array.from(dataTransfer.types ?? []);
  const hasFilePayload = transferTypes.includes('Files');
  if (!hasFilePayload) {
    return 'none';
  }

  const itemMimeTypes = Array.from(dataTransfer.items ?? [])
    .filter((item) => item.kind === 'file')
    .map((item) => item.type.toLowerCase())
    .filter((type) => type.length > 0);

  // When the browser exposes MIME types during drag-over, use them for instant feedback.
  if (itemMimeTypes.length > 0) {
    const hasDisallowedMime = itemMimeTypes.some((type) => !isAllowedMarkdownImageMimeType(type));
    return hasDisallowedMime ? 'invalid' : 'valid';
  }

  // Some browsers do not expose dragged file metadata until drop.
  // Keep the UX permissive during drag-over and validate strictly on drop.
  return 'valid';
};

export const getImageFilesFromDataTransfer = (dataTransfer?: DataTransfer | null): File[] => {
  const files = dataTransfer?.files ? Array.from(dataTransfer.files) : [];
  return getImageFiles(files);
};

export const getImageFilesFromClipboardData = (clipboardData?: DataTransfer | null): File[] => {
  const items = Array.from(clipboardData?.items ?? []);
  return items
    .filter((item) => item.kind === 'file')
    .map((item) => item.getAsFile())
    .filter((file): file is File => file !== null)
    .filter((file) => getImageFiles([file]).length > 0);
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
  const imageReferences = extractMarkdownImageReferences(markdown, { stopAtLineBreakAtTopLevel: true });

  for (let i = 0; i < imageReferences.length; i += 1) {
    const embeddedPath = extractEmbeddedStoragePathFromUrl(imageReferences[i].imageUrl);
    if (embeddedPath) {
      const normalized = embeddedPath.trim().replace(/^\/+/, '').split(/[?#]/)[0];
      if (!normalized.includes('..')) {
        paths.add(normalized);
      }
    }
  }

  return Array.from(paths);
};
