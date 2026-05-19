import { Readable } from 'node:stream';
import mime from 'mime-types';
import { logApp } from '../config/conf';
import { FunctionalError } from '../config/errors';
import { uploadToStorage } from './file-storage';
import { getFileContent } from './raw-file-storage';
import { getDraftContext } from '../utils/draftContext';
import { getDraftFilePrefix } from './draft-utils';
import {
  ALLOWED_EMBEDDED_IMAGE_MIME_TYPES,
  collectDataUriImagesFromMarkdown,
  DEFAULT_MAX_EMBEDDED_IMAGE_SIZE_BYTES,
  DEFAULT_MAX_TOTAL_EMBEDDED_IMAGE_SIZE_BYTES,
  extractMarkdownImageReferences,
  resolveEmbeddedStoragePathWithContext,
  rewriteMarkdownImageUrls,
} from './markdown-embedded-images';
import { UPDATE_OPERATION_REMOVE } from './utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase } from '../types/store';
import type { EditInput } from '../generated/graphql';
import type { InternalEditInput } from '../types/store';

export const MARKDOWN_FIELD_KEYS = ['description', 'x_opencti_description', 'content'];
const TEMP_IMAGE_TOKEN_REGEX = /([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/;
const EMBEDDED_IMAGE_EXPORT_FETCH_ATTEMPTS = 3;
const ALLOWED_EMBEDDED_IMAGE_MIME_TYPES_SET = new Set(ALLOWED_EMBEDDED_IMAGE_MIME_TYPES);

const visitObjectGraph = (
  node: unknown,
  seen: Set<object>,
  visitor: (valueByKey: Record<string, unknown>) => void,
): void => {
  if (!node || typeof node !== 'object') {
    return;
  }
  if (seen.has(node as object)) {
    return;
  }
  seen.add(node as object);

  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      visitObjectGraph(node[i], seen, visitor);
    }
    return;
  }

  const valueByKey = node as Record<string, unknown>;
  visitor(valueByKey);

  const values = Object.values(valueByKey);
  for (let i = 0; i < values.length; i += 1) {
    visitObjectGraph(values[i], seen, visitor);
  }
};

const visitObjectGraphAsync = async (
  node: unknown,
  seen: Set<object>,
  visitor: (valueByKey: Record<string, unknown>) => Promise<void>,
): Promise<void> => {
  if (!node || typeof node !== 'object') {
    return;
  }
  if (seen.has(node as object)) {
    return;
  }
  seen.add(node as object);

  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      await visitObjectGraphAsync(node[i], seen, visitor);
    }
    return;
  }

  const valueByKey = node as Record<string, unknown>;
  await visitor(valueByKey);

  const values = Object.values(valueByKey);
  for (let i = 0; i < values.length; i += 1) {
    await visitObjectGraphAsync(values[i], seen, visitor);
  }
};

const buildEmbeddedMarkdownImageFilename = (dedupeKey: string, mimeType: string): string => {
  const extension = mime.extension(mimeType) || 'bin';
  return `markdown-image-${dedupeKey.slice(0, 24)}.${extension}`;
};

export type RewriteEmbeddedDataUriOptions = {
  entityType: string;
  entityId: string;
  entity: BasicStoreBase;
  fileMarkings: string[];
};

export type ResolveEmbeddedImagesForExportOptions = {
  entityType: string;
  entityId: string;
};

const extractTempTokenFromImageUrl = (imageUrl: string): string | null => {
  const match = TEMP_IMAGE_TOKEN_REGEX.exec(imageUrl);
  return match ? match[1] : null;
};

export const collectTempImageTokensFromDescriptionFields = (payload: unknown): string[] => {
  const tokens: string[] = [];
  const seenNodes = new Set<object>();
  const seenTokens = new Set<string>();

  const addTokensFromMarkdown = (markdown: string) => {
    const references = extractMarkdownImageReferences(markdown);
    for (let i = 0; i < references.length; i += 1) {
      const token = extractTempTokenFromImageUrl(references[i].url);
      if (!token || seenTokens.has(token)) {
        continue;
      }
      seenTokens.add(token);
      tokens.push(token);
    }
  };

  visitObjectGraph(payload, seenNodes, (valueByKey) => {
    for (let i = 0; i < MARKDOWN_FIELD_KEYS.length; i += 1) {
      const markdownField = MARKDOWN_FIELD_KEYS[i];
      const fieldValue = valueByKey[markdownField];
      if (typeof fieldValue === 'string') {
        addTokensFromMarkdown(fieldValue);
      }
    }
  });
  return tokens;
};

export const rewriteTempImageTokensInDescriptions = (
  payload: unknown,
  tokenToUrl: Map<string, string>,
): void => {
  const seen = new Set<object>();

  const rewriteMarkdown = (markdown: string): string => {
    const { markdown: rewritten } = rewriteMarkdownImageUrls(markdown, (reference) => {
      const token = extractTempTokenFromImageUrl(reference.url);
      if (!token) {
        return undefined;
      }
      return tokenToUrl.get(token);
    });
    return rewritten;
  };

  visitObjectGraph(payload, seen, (valueByKey) => {
    for (let i = 0; i < MARKDOWN_FIELD_KEYS.length; i += 1) {
      const markdownField = MARKDOWN_FIELD_KEYS[i];
      const fieldValue = valueByKey[markdownField];
      if (typeof fieldValue === 'string') {
        valueByKey[markdownField] = rewriteMarkdown(fieldValue);
      }
    }
  });
};

export const rewriteEmbeddedDataUriImagesInDescriptions = async (
  context: AuthContext,
  user: AuthUser,
  payload: unknown,
  options: RewriteEmbeddedDataUriOptions,
): Promise<void> => {
  const allowedMimeTypes = new Set(ALLOWED_EMBEDDED_IMAGE_MIME_TYPES);
  const uploadedUriByDedupeKey = new Map<string, string>();
  const seen = new Set<object>();
  let totalDataUriSizeBytes = 0;

  const rewriteMarkdownDataUris = async (markdown: string): Promise<string> => {
    if (!markdown.includes('data:')) {
      return markdown;
    }

    const collected = collectDataUriImagesFromMarkdown(markdown, {
      allowedMimeTypes: ALLOWED_EMBEDDED_IMAGE_MIME_TYPES,
      maxImageSizeBytes: DEFAULT_MAX_EMBEDDED_IMAGE_SIZE_BYTES,
      maxTotalSizeBytes: DEFAULT_MAX_TOTAL_EMBEDDED_IMAGE_SIZE_BYTES,
      currentTotalSizeBytes: totalDataUriSizeBytes,
    });

    if (collected.totalImagesDetected === 0) {
      return markdown;
    }

    const replacementByDataUri = new Map<string, string>();
    for (let i = 0; i < collected.images.length; i += 1) {
      const image = collected.images[i];
      let replacementUri = uploadedUriByDedupeKey.get(image.dedupeKey);

      if (!replacementUri) {
        if (!allowedMimeTypes.has(image.mimeType as typeof ALLOWED_EMBEDDED_IMAGE_MIME_TYPES[number])) {
          throw FunctionalError('Unsupported markdown embedded image mime type', {
            mimeType: image.mimeType,
            entityType: options.entityType,
            entityId: options.entityId,
          });
        }

        const fileName = buildEmbeddedMarkdownImageFilename(image.dedupeKey, image.mimeType);
        const fileUpload = {
          createReadStream: () => Readable.from(image.bytes),
          filename: fileName,
          mimeType: image.mimeType,
        };
        const uploadPath = `embedded/${options.entityType}/${options.entityId}`;
        const { upload: uploadedFile } = await uploadToStorage(
          context,
          user,
          uploadPath,
          fileUpload,
          {
            entity: options.entity,
            file_markings: options.fileMarkings,
            noTriggerImport: true,
            meta: { mimetype: image.mimeType },
          },
        );
        replacementUri = `embedded/${uploadedFile.name}`;
        uploadedUriByDedupeKey.set(image.dedupeKey, replacementUri);
      }

      replacementByDataUri.set(image.dataUri, replacementUri);
    }

    totalDataUriSizeBytes += collected.totalSizeBytes;
    const { markdown: rewrittenMarkdown } = rewriteMarkdownImageUrls(markdown, (reference) => {
      return replacementByDataUri.get(reference.url);
    });
    return rewrittenMarkdown;
  };

  try {
    await visitObjectGraphAsync(payload, seen, async (valueByKey) => {
      for (let i = 0; i < MARKDOWN_FIELD_KEYS.length; i += 1) {
        const key = MARKDOWN_FIELD_KEYS[i];
        const value = valueByKey[key];
        if (typeof value === 'string') {
          valueByKey[key] = await rewriteMarkdownDataUris(value);
        }
      }
    });
  } catch (error) {
    throw FunctionalError('Failed to process markdown embedded images in descriptions', {
      entityType: options.entityType,
      entityId: options.entityId,
      cause: error,
    });
  }
};

export const rewriteEmbeddedDataUriImagesInUpdateInputs = async (
  context: AuthContext,
  user: AuthUser,
  updates: EditInput[],
  options: RewriteEmbeddedDataUriOptions,
): Promise<void> => {
  const payloadByKey = new Map<string, unknown>();

  for (let i = 0; i < updates.length; i += 1) {
    const updateInput = updates[i];
    const { key, value, operation } = updateInput;
    if (!MARKDOWN_FIELD_KEYS.includes(key)) {
      continue;
    }
    if (operation === UPDATE_OPERATION_REMOVE || !Array.isArray(value) || value.length === 0) {
      continue;
    }
    if (typeof value[0] === 'string') {
      payloadByKey.set(key, value[0]);
    }
  }

  if (payloadByKey.size === 0) {
    return;
  }

  const payload = Object.fromEntries(payloadByKey.entries());
  await rewriteEmbeddedDataUriImagesInDescriptions(context, user, payload, options);

  for (let i = 0; i < updates.length; i += 1) {
    const updateInput = updates[i];
    if (!MARKDOWN_FIELD_KEYS.includes(updateInput.key)) {
      continue;
    }
    const rewrittenValue = payloadByKey.has(updateInput.key)
      ? (payload as Record<string, unknown>)[updateInput.key]
      : undefined;
    if (typeof rewrittenValue === 'string') {
      updateInput.value = [rewrittenValue];
    }
  }
};

const resolveEmbeddedImageDataUriForExport = async (
  context: AuthContext,
  storagePath: string,
  mimeType: string,
  fetchAttempts: number,
): Promise<string | null> => {
  const draftContext = getDraftContext(context);
  const draftPrefix = draftContext ? getDraftFilePrefix(draftContext) : null;
  const candidatePaths = [storagePath];
  if (draftPrefix && !storagePath.startsWith(draftPrefix)) {
    candidatePaths.push(`${draftPrefix}${storagePath}`);
  }

  for (let pathIndex = 0; pathIndex < candidatePaths.length; pathIndex += 1) {
    const candidatePath = candidatePaths[pathIndex];
    for (let attempt = 1; attempt <= fetchAttempts; attempt += 1) {
      try {
        const base64Data = await getFileContent(candidatePath, 'base64');
        if (base64Data) {
          return `data:${mimeType};base64,${base64Data}`;
        }
      } catch (error) {
        if (attempt === fetchAttempts) {
          logApp.warn('[OPENCTI] Unable to fetch embedded markdown image during STIX export', {
            storagePath,
            candidatePath,
            attempts: fetchAttempts,
            cause: error,
          });
        }
      }
    }
  }

  return null;
};

const resolveEmbeddedImagesInMarkdownDescriptionForExport = async (
  context: AuthContext,
  markdown: string,
  options: ResolveEmbeddedImagesForExportOptions,
): Promise<string> => {
  const embeddedReferences = extractMarkdownImageReferences(markdown)
    .filter((reference) => reference.isEmbeddedStorage && reference.embeddedStoragePath);

  if (embeddedReferences.length === 0) {
    return markdown;
  }

  const uniqueStoragePaths = Array.from(new Set(embeddedReferences.map((reference) => {
    return resolveEmbeddedStoragePathWithContext(reference.embeddedStoragePath as string, {
      entityType: options.entityType,
      entityId: options.entityId,
    });
  })));
  const uriByStoragePath = new Map<string, string | null>();

  for (let i = 0; i < uniqueStoragePaths.length; i += 1) {
    const storagePath = uniqueStoragePaths[i];
    const detectedMime = mime.lookup(storagePath);
    if (!detectedMime || !ALLOWED_EMBEDDED_IMAGE_MIME_TYPES_SET.has(detectedMime as typeof ALLOWED_EMBEDDED_IMAGE_MIME_TYPES[number])) {
      logApp.warn('[OPENCTI] Unsupported embedded markdown image mime type during STIX export, keeping original URI', {
        storagePath,
        mimeType: detectedMime || null,
      });
      uriByStoragePath.set(storagePath, null);
      continue;
    }

    const dataUri = await resolveEmbeddedImageDataUriForExport(
      context,
      storagePath,
      detectedMime as string,
      EMBEDDED_IMAGE_EXPORT_FETCH_ATTEMPTS,
    );
    if (!dataUri) {
      logApp.warn('[OPENCTI] Unable to resolve embedded markdown image during STIX export after retries, keeping original URI', {
        storagePath,
        attempts: EMBEDDED_IMAGE_EXPORT_FETCH_ATTEMPTS,
      });
      uriByStoragePath.set(storagePath, null);
      continue;
    }

    uriByStoragePath.set(storagePath, dataUri);
  }

  const { markdown: rewrittenMarkdown } = rewriteMarkdownImageUrls(markdown, (reference) => {
    if (!reference.embeddedStoragePath) {
      return undefined;
    }
    const resolvedStoragePath = resolveEmbeddedStoragePathWithContext(reference.embeddedStoragePath, {
      entityType: options.entityType,
      entityId: options.entityId,
    });
    const resolvedUri = uriByStoragePath.get(resolvedStoragePath);
    return resolvedUri ?? undefined;
  });

  return rewrittenMarkdown;
};

export const resolveEmbeddedImagesInDescriptionFieldsForExport = async <T extends object>(
  context: AuthContext,
  payload: T,
  options: ResolveEmbeddedImagesForExportOptions,
): Promise<T> => {
  const hasEmbeddedStorageRef = (s: string) => extractMarkdownImageReferences(s).some((reference) => reference.isEmbeddedStorage);
  const payloadByKey = payload as Record<string, unknown>;
  const nextPayload = { ...payload } as T;
  const nextPayloadByKey = nextPayload as Record<string, unknown>;

  for (let i = 0; i < MARKDOWN_FIELD_KEYS.length; i += 1) {
    const key = MARKDOWN_FIELD_KEYS[i];
    const value = payloadByKey[key];
    if (typeof value === 'string' && hasEmbeddedStorageRef(value)) {
      nextPayloadByKey[key] = await resolveEmbeddedImagesInMarkdownDescriptionForExport(context, value, options);
    }
  }

  return nextPayload;
};

export const rewriteMarkdownPatchUpdatesForExport = async (
  context: AuthContext,
  updates: InternalEditInput[],
  options: ResolveEmbeddedImagesForExportOptions,
): Promise<InternalEditInput[]> => {
  const rewrittenPatches = [];

  for (let i = 0; i < updates.length; i += 1) {
    const patch = updates[i];
    if (!MARKDOWN_FIELD_KEYS.includes(patch.key) || !Array.isArray(patch.value) || patch.value.length === 0) {
      rewrittenPatches.push(patch);
      continue;
    }

    // Only markdown strings are rewritten; non-string patch values are kept as-is.
    const rewrittenValues = await Promise.all(patch.value.map(async (currentValue) => {
      if (typeof currentValue !== 'string') {
        return currentValue;
      }

      const rewrittenPayload = await resolveEmbeddedImagesInDescriptionFieldsForExport(
        context,
        { [patch.key]: currentValue },
        options,
      );

      const rewrittenMarkdown = rewrittenPayload[patch.key];

      return typeof rewrittenMarkdown === 'string' ? rewrittenMarkdown : currentValue;
    }));

    rewrittenPatches.push({
      ...patch,
      value: rewrittenValues,
    });
  }

  return rewrittenPatches;
};
