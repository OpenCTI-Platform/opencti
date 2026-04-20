import { createHash } from 'node:crypto';
import { FunctionalError } from '../config/errors';

const STORAGE_GET_EMBEDDED_PREFIX = '/storage/get/embedded/';
const STORAGE_GET_PREFIX = '/storage/get/';
const STORAGE_VIEW_EMBEDDED_PREFIX = '/storage/view/embedded/';
const STORAGE_VIEW_EMBEDDED_PREFIX_ENCODED = '/storage/view/embedded%2F';

export const ALLOWED_EMBEDDED_IMAGE_MIME_TYPES = [
  'image/png',
  'image/jpeg',
  'image/gif',
  'image/webp',
  'image/svg+xml',
] as const;

export const DEFAULT_MAX_EMBEDDED_IMAGE_SIZE_BYTES = 5 * 1024 * 1024;
export const DEFAULT_MAX_TOTAL_EMBEDDED_IMAGE_SIZE_BYTES = 20 * 1024 * 1024;

export interface EmbeddedMarkdownImageReference {
  altText: string;
  title?: string;
  url: string;
  start: number;
  end: number;
  urlStart: number;
  urlEnd: number;
  isEmbeddedStorage: boolean;
  embeddedStoragePath?: string;
}

export interface ParsedDataUriImage {
  dataUri: string;
  mimeType: string;
  bytes: Buffer;
  byteLength: number;
  dedupeKey: string;
}

export interface DataUriParsingOptions {
  allowedMimeTypes?: readonly string[];
  maxImageSizeBytes?: number;
  maxTotalSizeBytes?: number;
  currentTotalSizeBytes?: number;
}

export interface CollectedMarkdownDataUriImage {
  dedupeKey: string;
  dataUri: string;
  mimeType: string;
  bytes: Buffer;
  byteLength: number;
  occurrences: EmbeddedMarkdownImageReference[];
}

export interface CollectedMarkdownDataUriImages {
  images: CollectedMarkdownDataUriImage[];
  totalImagesDetected: number;
  totalSizeBytes: number;
}

export interface EmbeddedMarkdownStoragePathCollectionOptions {
  entityType?: string;
  entityId?: string;
}

const MARKDOWN_FIELD_KEYS = ['description', 'x_opencti_description', 'content'];

interface ParsedMarkdownDestination {
  url: string;
  title?: string;
  urlStart: number;
  urlEnd: number;
}

const DATA_URI_IMAGE_REGEX = /^data:([^;,\s]+)(;base64)?,([\s\S]*)$/i;

const normalizeMimeType = (mimeType: string) => mimeType.toLowerCase().trim();

const getAllowedMimeTypes = (allowedMimeTypes?: readonly string[]) => {
  const source = allowedMimeTypes ?? ALLOWED_EMBEDDED_IMAGE_MIME_TYPES;
  return new Set(source.map((mimeType) => normalizeMimeType(mimeType)));
};

const isLikelyBase64 = (payload: string) => {
  if (payload.length === 0 || payload.length % 4 !== 0) {
    return false;
  }
  return /^[A-Za-z0-9+/]+={0,2}$/.test(payload);
};

const parseMarkdownImageDestination = (destination: string): ParsedMarkdownDestination | null => {
  let index = 0;
  while (index < destination.length && /\s/.test(destination[index])) {
    index += 1;
  }

  if (index >= destination.length) {
    return null;
  }

  let urlStart = index;
  let urlEnd: number;

  if (destination[index] === '<') {
    const closingIndex = destination.indexOf('>', index + 1);
    if (closingIndex < 0) {
      return null;
    }
    urlStart = index + 1;
    urlEnd = closingIndex;
    index = closingIndex + 1;
  } else {
    while (index < destination.length && !/\s/.test(destination[index])) {
      index += 1;
    }
    urlEnd = index;
  }

  if (urlEnd <= urlStart) {
    return null;
  }

  while (index < destination.length && /\s/.test(destination[index])) {
    index += 1;
  }

  let title: string | undefined;
  if (index < destination.length && (destination[index] === '"' || destination[index] === '\'')) {
    const quote = destination[index];
    const closingQuote = destination.indexOf(quote, index + 1);
    if (closingQuote > index) {
      title = destination.slice(index + 1, closingQuote);
    }
  }

  return {
    url: destination.slice(urlStart, urlEnd),
    title,
    urlStart,
    urlEnd,
  };
};

export const extractEmbeddedStoragePathFromUrl = (url: string): string | undefined => {
  const trimmed = url.trim();
  const decodeEmbeddedEncodedPath = (encodedPath: string): string | undefined => {
    try {
      return decodeURIComponent(encodedPath).split(/[?#]/)[0];
    } catch {
      return undefined;
    }
  };

  if (trimmed.startsWith(STORAGE_GET_EMBEDDED_PREFIX)) {
    return trimmed.slice(STORAGE_GET_PREFIX.length).split(/[?#]/)[0];
  }

  if (trimmed.startsWith(STORAGE_VIEW_EMBEDDED_PREFIX)) {
    return trimmed.slice(STORAGE_VIEW_EMBEDDED_PREFIX.length - 'embedded/'.length).split(/[?#]/)[0];
  }

  if (trimmed.startsWith(STORAGE_VIEW_EMBEDDED_PREFIX_ENCODED)) {
    // /storage/view/embedded%2FType%2Fid%2Ffile.ext — decode and normalise to embedded/...
    const encodedPath = trimmed.slice('/storage/view/'.length).split(/[?#]/)[0];
    return decodeEmbeddedEncodedPath(encodedPath);
  }

  try {
    const parsed = new URL(trimmed);
    const pathname = parsed.pathname;
    if (pathname.startsWith(STORAGE_GET_EMBEDDED_PREFIX)) {
      return pathname.slice(STORAGE_GET_PREFIX.length);
    }
    if (pathname.startsWith(STORAGE_VIEW_EMBEDDED_PREFIX)) {
      return pathname.slice(STORAGE_VIEW_EMBEDDED_PREFIX.length - 'embedded/'.length);
    }
    if (/^\/storage\/view\/embedded%2f/i.test(pathname)) {
      const encodedPath = pathname.slice('/storage/view/'.length);
      return decodeEmbeddedEncodedPath(encodedPath);
    }
  } catch {
    // Ignore invalid absolute URLs.
  }

  return undefined;
};

export const extractMarkdownImageReferences = (markdown: string): EmbeddedMarkdownImageReference[] => {
  const references: EmbeddedMarkdownImageReference[] = [];

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
    const parsedDestination = parseMarkdownImageDestination(destination);
    if (!parsedDestination) {
      cursor = index + 1;
      continue;
    }

    const altText = markdown.slice(imageStart + 2, altEnd);
    const urlStart = destinationStart + parsedDestination.urlStart;
    const urlEnd = destinationStart + parsedDestination.urlEnd;
    const embeddedStoragePath = extractEmbeddedStoragePathFromUrl(parsedDestination.url);

    references.push({
      altText,
      title: parsedDestination.title,
      url: parsedDestination.url,
      start: imageStart,
      end: index + 1,
      urlStart,
      urlEnd,
      isEmbeddedStorage: !!embeddedStoragePath,
      embeddedStoragePath,
    });

    cursor = index + 1;
  }

  return references;
};

export const rewriteMarkdownImageUrls = (
  markdown: string,
  replacer: (reference: EmbeddedMarkdownImageReference) => string | undefined,
): { markdown: string; replacedCount: number } => {
  const references = extractMarkdownImageReferences(markdown);
  if (references.length === 0) {
    return { markdown, replacedCount: 0 };
  }

  let updated = markdown;
  let replacedCount = 0;
  let offset = 0;

  for (const reference of references) {
    const replacement = replacer(reference);
    if (!replacement || replacement === reference.url) {
      continue;
    }

    const from = reference.urlStart + offset;
    const to = reference.urlEnd + offset;
    updated = `${updated.slice(0, from)}${replacement}${updated.slice(to)}`;
    offset += replacement.length - (to - from);
    replacedCount += 1;
  }

  return { markdown: updated, replacedCount };
};

export const buildStorageGetUri = (storagePath: string): string => {
  const normalized = storagePath.replace(/^\/+/, '');
  if (normalized.startsWith('storage/get/')) {
    return `/${normalized}`;
  }
  return `${STORAGE_GET_PREFIX}${normalized}`;
};

export const buildEmbeddedStorageGetUri = (
  entityType: string,
  entityId: string,
  fileName: string,
): string => {
  return buildStorageGetUri(`embedded/${entityType}/${entityId}/${fileName}`);
};

export const dedupeKeyFromBytes = (bytes: Buffer): string => {
  return createHash('sha256').update(bytes).digest('hex');
};

export const parseDataUriImage = (
  dataUri: string,
  options: DataUriParsingOptions = {},
): ParsedDataUriImage => {
  const match = DATA_URI_IMAGE_REGEX.exec(dataUri);
  if (!match) {
    throw FunctionalError('Invalid data URI image format');
  }

  const mimeType = normalizeMimeType(match[1]);
  const isBase64 = !!match[2];
  const payload = match[3].trim();

  const allowedMimeTypes = getAllowedMimeTypes(options.allowedMimeTypes);
  if (!allowedMimeTypes.has(mimeType)) {
    throw FunctionalError(`Unsupported data URI image mime type: ${mimeType}`);
  }

  if (!isBase64) {
    throw FunctionalError('Data URI image payload must be base64 encoded');
  }

  if (!isLikelyBase64(payload)) {
    throw FunctionalError('Invalid base64 payload in data URI image');
  }

  const bytes = Buffer.from(payload, 'base64');
  if (bytes.byteLength === 0) {
    throw FunctionalError('Data URI image payload is empty');
  }

  const maxImageSizeBytes = options.maxImageSizeBytes ?? DEFAULT_MAX_EMBEDDED_IMAGE_SIZE_BYTES;
  if (bytes.byteLength > maxImageSizeBytes) {
    throw FunctionalError(`Data URI image exceeds max size (${maxImageSizeBytes} bytes)`);
  }

  const maxTotalSizeBytes = options.maxTotalSizeBytes ?? DEFAULT_MAX_TOTAL_EMBEDDED_IMAGE_SIZE_BYTES;
  const currentTotalSizeBytes = options.currentTotalSizeBytes ?? 0;
  if (currentTotalSizeBytes + bytes.byteLength > maxTotalSizeBytes) {
    throw FunctionalError(`Data URI images exceed max total size (${maxTotalSizeBytes} bytes)`);
  }

  return {
    dataUri,
    mimeType,
    bytes,
    byteLength: bytes.byteLength,
    dedupeKey: dedupeKeyFromBytes(bytes),
  };
};

export const collectDataUriImagesFromMarkdown = (
  markdown: string,
  options: DataUriParsingOptions = {},
): CollectedMarkdownDataUriImages => {
  const references = extractMarkdownImageReferences(markdown);
  const byDedupeKey = new Map<string, CollectedMarkdownDataUriImage>();

  let totalImagesDetected = 0;
  let totalSizeBytes = 0;

  for (const reference of references) {
    if (!reference.url.startsWith('data:')) {
      continue;
    }

    const parsed = parseDataUriImage(reference.url, {
      ...options,
      currentTotalSizeBytes: totalSizeBytes,
    });

    totalImagesDetected += 1;
    totalSizeBytes += parsed.byteLength;

    const existing = byDedupeKey.get(parsed.dedupeKey);
    if (existing) {
      existing.occurrences.push(reference);
      continue;
    }

    byDedupeKey.set(parsed.dedupeKey, {
      dedupeKey: parsed.dedupeKey,
      dataUri: parsed.dataUri,
      mimeType: parsed.mimeType,
      bytes: parsed.bytes,
      byteLength: parsed.byteLength,
      occurrences: [reference],
    });
  }

  return {
    images: Array.from(byDedupeKey.values()),
    totalImagesDetected,
    totalSizeBytes,
  };
};

export const collectEmbeddedStoragePathsFromMarkdownFields = (
  payload: unknown,
  options: EmbeddedMarkdownStoragePathCollectionOptions = {},
): Set<string> => {
  const seen = new Set<object>();
  const collected = new Set<string>();
  const entityPrefix = options.entityType && options.entityId
    ? `embedded/${options.entityType}/${options.entityId}/`
    : undefined;

  const addIfEmbeddedPath = (markdown: string) => {
    const references = extractMarkdownImageReferences(markdown);
    for (let i = 0; i < references.length; i += 1) {
      const embeddedStoragePath = references[i].embeddedStoragePath;
      if (!embeddedStoragePath) {
        continue;
      }
      const normalizedPath = embeddedStoragePath.trim().replace(/^\/+/, '').split(/[?#]/)[0];
      if (normalizedPath.includes('..')) {
        continue;
      }
      if (entityPrefix && !normalizedPath.startsWith(entityPrefix)) {
        continue;
      }
      collected.add(normalizedPath);
    }
  };

  const visit = (node: unknown): void => {
    if (!node || typeof node !== 'object') {
      return;
    }
    if (seen.has(node as object)) {
      return;
    }
    seen.add(node as object);

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        visit(node[i]);
      }
      return;
    }

    const valueByKey = node as Record<string, unknown>;
    for (let i = 0; i < MARKDOWN_FIELD_KEYS.length; i += 1) {
      const markdownField = MARKDOWN_FIELD_KEYS[i];
      const fieldValue = valueByKey[markdownField];
      if (typeof fieldValue === 'string') {
        addIfEmbeddedPath(fieldValue);
      }
    }

    const descriptions = valueByKey.descriptions;
    if (Array.isArray(descriptions)) {
      for (let i = 0; i < descriptions.length; i += 1) {
        if (typeof descriptions[i] === 'string') {
          addIfEmbeddedPath(descriptions[i]);
        }
      }
    }

    const entries = Object.entries(valueByKey);
    for (let i = 0; i < entries.length; i += 1) {
      const [key, value] = entries[i];
      if (MARKDOWN_FIELD_KEYS.includes(key) || key === 'descriptions') {
        continue;
      }
      visit(value);
    }
  };

  visit(payload);
  return collected;
};

export const findRemovedEmbeddedStoragePathsFromMarkdownFields = (
  previousPayload: unknown,
  nextPayload: unknown,
  options: EmbeddedMarkdownStoragePathCollectionOptions = {},
): string[] => {
  const previousPaths = collectEmbeddedStoragePathsFromMarkdownFields(previousPayload, options);
  const nextPaths = collectEmbeddedStoragePathsFromMarkdownFields(nextPayload, options);
  const removedPaths: string[] = [];

  previousPaths.forEach((path) => {
    if (!nextPaths.has(path)) {
      removedPaths.push(path);
    }
  });

  return removedPaths;
};
