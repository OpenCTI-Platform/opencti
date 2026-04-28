import { defaultUrlTransform } from 'react-markdown';
import { TEMP_IMAGE_SCHEME } from '../fields/markdownField/core/markdownImagePreviewUtils';
import { extractMarkdownImageReferences } from '../fields/markdownField/core/markdownImageParsingUtils';

export type MarkdownPreviewImage = {
  src: string;
  alt: string;
};

const STORAGE_IMAGE_PATHS = ['/storage/view', '/storage/get'];

export const isAllowedUploadedImageUrl = (url: string): boolean => {
  if (!url) return false;
  if (url.startsWith(TEMP_IMAGE_SCHEME)) return true;
  if (STORAGE_IMAGE_PATHS.some((path) => url.includes(path))) return true;
  return defaultUrlTransform(url) !== '';
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
