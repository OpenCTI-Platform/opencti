import { defaultUrlTransform } from 'react-markdown';
import { TEMP_IMAGE_SCHEME } from '../fields/markdownField/markdownImageTempUtils';
import type { MarkdownPreviewImage } from './MarkdownImagePreviewModal';

const STORAGE_IMAGE_PATHS = ['/storage/view', '/storage/get'];

export const isAllowedUploadedImageUrl = (url: string): boolean => {
  if (!url) return false;
  if (url.startsWith(TEMP_IMAGE_SCHEME)) return true;
  if (STORAGE_IMAGE_PATHS.some((path) => url.includes(path))) return true;
  return defaultUrlTransform(url) !== '';
};

export const parseMarkdownImageDestination = (destination: string): { url: string; urlStart: number; urlEnd: number } | null => {
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
  } else {
    while (index < destination.length && !/\s/.test(destination[index])) {
      index += 1;
    }
    urlEnd = index;
  }

  if (urlEnd <= urlStart) {
    return null;
  }

  return {
    url: destination.slice(urlStart, urlEnd),
    urlStart,
    urlEnd,
  };
};

export const extractMarkdownPreviewImages = (
  markdown: string,
  resolveImageUrl: (url: string) => string | null,
): MarkdownPreviewImage[] => {
  const images: MarkdownPreviewImage[] = [];
  const dedupe = new Set<string>();
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
    const parsed = parseMarkdownImageDestination(destination);
    const altText = markdown.slice(imageStart + 2, altEnd);
    if (parsed) {
      const resolved = resolveImageUrl(parsed.url);
      if (resolved && isAllowedUploadedImageUrl(parsed.url)) {
        const key = `${resolved}|${altText}`;
        if (!dedupe.has(key)) {
          dedupe.add(key);
          images.push({ src: resolved, alt: altText || '' });
        }
      }
    }

    cursor = index + 1;
  }

  return images;
};
