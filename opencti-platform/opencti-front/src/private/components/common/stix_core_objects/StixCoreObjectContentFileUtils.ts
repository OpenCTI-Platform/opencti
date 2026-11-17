import { createSearchParams } from 'react-router';

// Images the Content tab can preview. Other image types (GIF, SVG...) stay hidden.
const CONTENT_TAB_IMAGE_MIME_TYPES = ['image/png', 'image/jpeg'];

// Every file type listed in the Files section of the Content tab.
const CONTENT_TAB_MIME_TYPES = [
  'application/pdf',
  'text/plain',
  'text/html',
  'text/markdown',
  ...CONTENT_TAB_IMAGE_MIME_TYPES,
];

// Entities whose Data tab exists without a Content tab.
const ENTITY_TYPES_WITHOUT_CONTENT_TAB = ['Note', 'Observed-Data'];

const MIME_TYPES_BY_EXTENSION: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  pdf: 'application/pdf',
};

type MimeType = string | null | undefined;

export const isContentTabImage = (mimeType: MimeType) => !!mimeType && CONTENT_TAB_IMAGE_MIME_TYPES.includes(mimeType);

// Files rendered as they are, never fetched as text nor opened in the editor.
export const isPreviewOnlyFile = (mimeType: MimeType) => mimeType === 'application/pdf' || isContentTabImage(mimeType);

/**
 * Keeps only the files the Content tab can display (PDF, text, HTML, Markdown, PNG, JPEG),
 * sorted by last modified date, oldest first. Files without a mime type are dropped.
 */
export const filterContentTabFiles =<T extends { lastModified: string; metaData?: { mimetype?: MimeType } | null }>(files: T[]): T[] => {
  return files
    .filter((file) => !!file.metaData?.mimetype && CONTENT_TAB_MIME_TYPES.includes(file.metaData.mimetype))
    .sort((a, b) => (a.lastModified < b.lastModified ? -1 : Number(a.lastModified > b.lastModified)));
};

// A file just uploaded is selected before the refetch lists it: fall back on its extension.
export const resolveContentFileMimeType = (fileId: string, knownMimeType: MimeType): string | undefined => {
  if (knownMimeType) return knownMimeType;
  const extension = fileId.split('.').pop()?.toLowerCase() ?? '';
  return MIME_TYPES_BY_EXTENSION[extension];
};

// Link from the Data tab to the preview of an image in the Content tab, null when not applicable.
export const getContentTabImagePreviewPath = (pathname: string, entityType: string, fileId: string, mimeType: MimeType): string | null => {
  if (!isContentTabImage(mimeType) || ENTITY_TYPES_WITHOUT_CONTENT_TAB.includes(entityType) || !pathname.endsWith('/files')) {
    return null;
  }
  const search = createSearchParams({ forceFile: 'true', currentFileId: fileId });
  return `${pathname.slice(0, -'/files'.length)}/content?${search}`;
};
