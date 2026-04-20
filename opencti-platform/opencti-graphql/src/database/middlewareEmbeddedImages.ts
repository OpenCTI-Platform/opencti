import { Readable } from 'node:stream';
import mime from 'mime-types';
import { FunctionalError } from '../config/errors';
import { uploadToStorage } from './file-storage';
import {
  ALLOWED_EMBEDDED_IMAGE_MIME_TYPES,
  collectDataUriImagesFromMarkdown,
  DEFAULT_MAX_EMBEDDED_IMAGE_SIZE_BYTES,
  DEFAULT_MAX_TOTAL_EMBEDDED_IMAGE_SIZE_BYTES,
  rewriteMarkdownImageUrls,
} from './markdown-embedded-images';
import { UPDATE_OPERATION_REMOVE } from './utils';
import type { AuthContext, AuthUser } from '../types/user';
import type { BasicStoreBase } from '../types/store';
import type { EditInput } from '../generated/graphql';

const MARKDOWN_FIELD_KEYS = ['description', 'x_opencti_description', 'content'];

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
        const { upload: uploadedFile } = await uploadToStorage(
          context,
          user,
          `embedded/${options.entityType}/${options.entityId}`,
          fileUpload,
          {
            entity: options.entity,
            file_markings: options.fileMarkings,
            noTriggerImport: true,
            meta: { mimetype: image.mimeType },
          },
        );
        replacementUri = `/storage/get/${uploadedFile.id}`;
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

  const visit = async (node: unknown): Promise<void> => {
    if (!node || typeof node !== 'object') {
      return;
    }

    if (seen.has(node as object)) {
      return;
    }
    seen.add(node as object);

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i += 1) {
        await visit(node[i]);
      }
      return;
    }

    for (let i = 0; i < MARKDOWN_FIELD_KEYS.length; i += 1) {
      const key = MARKDOWN_FIELD_KEYS[i];
      const value = (node as Record<string, unknown>)[key];
      if (typeof value === 'string') {
        (node as Record<string, unknown>)[key] = await rewriteMarkdownDataUris(value);
      }
    }

    const descriptions = (node as Record<string, unknown>).descriptions;
    if (Array.isArray(descriptions)) {
      for (let i = 0; i < descriptions.length; i += 1) {
        if (typeof descriptions[i] === 'string') {
          descriptions[i] = await rewriteMarkdownDataUris(descriptions[i]);
        }
      }
    }

    const entries = Object.entries(node as Record<string, unknown>);
    for (let i = 0; i < entries.length; i += 1) {
      const [key, value] = entries[i];
      if (MARKDOWN_FIELD_KEYS.includes(key) || key === 'descriptions') {
        continue;
      }
      await visit(value);
    }
  };

  try {
    await visit(payload);
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
  const updateKeysToRewrite = new Set([...MARKDOWN_FIELD_KEYS, 'descriptions']);
  const payloadByKey = new Map<string, unknown>();

  for (let i = 0; i < updates.length; i += 1) {
    const updateInput = updates[i];
    const { key, value, operation } = updateInput;
    if (!updateKeysToRewrite.has(key)) {
      continue;
    }
    if (operation === UPDATE_OPERATION_REMOVE || !Array.isArray(value) || value.length === 0) {
      continue;
    }
    if (key === 'descriptions') {
      if (value.some((entry) => typeof entry === 'string')) {
        payloadByKey.set(key, [...value]);
      }
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
    if (!updateKeysToRewrite.has(updateInput.key)) {
      continue;
    }
    const rewrittenValue = payloadByKey.has(updateInput.key)
      ? (payload as Record<string, unknown>)[updateInput.key]
      : undefined;
    if (updateInput.key === 'descriptions' && Array.isArray(rewrittenValue)) {
      updateInput.value = rewrittenValue;
      continue;
    }
    if (typeof rewrittenValue === 'string') {
      updateInput.value = [rewrittenValue];
    }
  }
};
