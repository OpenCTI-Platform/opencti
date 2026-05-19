export const resolveNoteEmbeddedImageUrl = (url: string, noteId: string): string | null => {
  if (!url) {
    return null;
  }

  const normalizedUrl = url.startsWith('/') ? url.slice(1) : url;
  if (!normalizedUrl.startsWith('embedded/')) {
    return url;
  }

  const embeddedPath = normalizedUrl.slice('embedded/'.length);
  if (!embeddedPath) {
    return null;
  }

  if (normalizedUrl.split('/').length >= 4) {
    return `/storage/view/${encodeURIComponent(normalizedUrl)}`;
  }

  if (!noteId) {
    return null;
  }

  return `/storage/view/${encodeURIComponent(`embedded/Note/${noteId}/${embeddedPath}`)}`;
};
