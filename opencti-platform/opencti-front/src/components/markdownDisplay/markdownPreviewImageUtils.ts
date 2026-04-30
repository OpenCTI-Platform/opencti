import { defaultUrlTransform } from 'react-markdown';
import { TEMP_IMAGE_SCHEME } from '../fields/markdownField/core/markdownImagePreviewUtils';
import { extractMarkdownImageReferences } from '../fields/markdownField/core/markdownImageParsingUtils';

export type MarkdownPreviewImage = {
  src: string;
  alt: string;
};

const STORAGE_IMAGE_PATHS = ['/storage/view', '/storage/get'];
const EMBEDDED_IMAGE_PATH_PREFIXES = ['embedded/', '/embedded/'];

const hasUrlScheme = (url: string): boolean => /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(url);

const isAllowedRelativeStoragePath = (url: string): boolean => {
  return STORAGE_IMAGE_PATHS.some((path) => url.startsWith(path));
};

const isAllowedHttpUrl = (url: string): boolean => {
  if (defaultUrlTransform(url) === '') {
    return false;
  }
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
};

export const isAllowedUploadedImageUrl = (url: string): boolean => {
  if (!url) return false;
  const normalizedUrl = url.trim();
  if (!normalizedUrl) return false;
  if (normalizedUrl.startsWith(TEMP_IMAGE_SCHEME)) return true;
  if (EMBEDDED_IMAGE_PATH_PREFIXES.some((prefix) => normalizedUrl.startsWith(prefix))) {
    return true;
  }
  if (normalizedUrl.startsWith('/')) {
    return isAllowedRelativeStoragePath(normalizedUrl);
  }
  if (hasUrlScheme(normalizedUrl)) {
    return isAllowedHttpUrl(normalizedUrl);
  }
  return false;
};

export const extractMarkdownPreviewImages = (
  markdown: string,
  resolveImageUrl: (url: string) => string | null,
): MarkdownPreviewImage[] => {
  const images: MarkdownPreviewImage[] = [];
  const dedupe = new Set<string>();
  const imageReferences = extractMarkdownImageReferences(markdown);

  for (let i = 0; i < imageReferences.length; i += 1) {
    const { imageUrl, altText } = imageReferences[i];
    const resolved = resolveImageUrl(imageUrl);
    if (resolved && isAllowedUploadedImageUrl(imageUrl)) {
      const key = `${resolved}|${altText}`;
      if (!dedupe.has(key)) {
        dedupe.add(key);
        images.push({ src: resolved, alt: altText || '' });
      }
    }
  }

  return images;
};
