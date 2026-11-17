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

// Containers with their own editable content (the "content" attribute), shown above the files in the Content tab.
export const CONTAINER_TYPES_WITH_CONTENT = ['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'];

export const isContainerWithContent = (entityType: string) => CONTAINER_TYPES_WITH_CONTENT.includes(entityType);

// Entities whose Data tab exists without a Content tab.
const ENTITY_TYPES_WITHOUT_CONTENT_TAB = ['Note', 'Observed-Data'];

// Entities whose files may be malicious samples: they keep the download warning (encrypted archive or raw file)
// instead of an in-app preview link.
const ENTITY_TYPES_WITH_UNSAFE_FILES = ['Artifact'];

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
export const filterContentTabFiles = <T extends { lastModified: string; metaData?: { mimetype?: MimeType } | null }>(files: T[]): T[] => {
  return files
    .filter((file) => !!file.metaData?.mimetype && CONTENT_TAB_MIME_TYPES.includes(file.metaData.mimetype))
    .sort((a, b) => (a.lastModified < b.lastModified ? -1 : Number(a.lastModified > b.lastModified)));
};

/**
 * Returns the mime type of a file of the Content tab.
 * A file just uploaded is selected before the refetch lists it, so its mime type is not known yet:
 * it is then guessed from the extension of the file id (PNG, JPG/JPEG, PDF only).
 *
 * @param fileId storage id of the file, e.g. `import/Report/<id>/screenshot.png`
 * @param knownMimeType mime type of the listed file, if the file is already listed
 * @returns the known mime type, else the one guessed from the extension, else `undefined`
 */
export const resolveContentFileMimeType = (fileId: string, knownMimeType: MimeType): string | undefined => {
  if (knownMimeType) return knownMimeType;
  const extension = fileId.split('.').pop()?.toLowerCase() ?? '';
  return MIME_TYPES_BY_EXTENSION[extension];
};

/**
 * Builds the link from an entity Data tab to the preview of an image in its Content tab.
 * The file is forced as the selection, like the deep links of Ask AI.
 *
 * @param pathname current route, the Data tab of the entity (ending with `/files`)
 * @param entityType type of the entity owning the file
 * @param fileId storage id of the file
 * @param mimeType mime type of the file
 * @returns the Content tab path with `forceFile` and `currentFileId` search params, or `null` when the file is
 * not a PNG / JPEG, the entity has no Content tab (Note, Observed-Data), its files may be malicious (Artifact)
 * or the route is not an entity Data tab
 */
export const getContentTabImagePreviewPath = (pathname: string, entityType: string, fileId: string, mimeType: MimeType): string | null => {
  if (
    !isContentTabImage(mimeType)
    || ENTITY_TYPES_WITHOUT_CONTENT_TAB.includes(entityType)
    || ENTITY_TYPES_WITH_UNSAFE_FILES.includes(entityType)
    || !pathname.endsWith('/files')
  ) {
    return null;
  }
  const search = createSearchParams({ forceFile: 'true', currentFileId: fileId });
  return `${pathname.slice(0, -'/files'.length)}/content?${search}`;
};
