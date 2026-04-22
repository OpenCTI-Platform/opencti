export type MarkdownImageReference = {
  altText: string;
  imageUrl: string;
};

type ExtractMarkdownImageReferencesOptions = {
  stopAtLineBreakAtTopLevel?: boolean;
};

export const parseMarkdownImageDestination = (destination: string): string | null => {
  let index = 0;
  while (index < destination.length && /\s/.test(destination[index])) {
    index += 1;
  }

  if (index >= destination.length) {
    return null;
  }

  if (destination[index] === '<') {
    const closing = destination.indexOf('>', index + 1);
    if (closing < 0) {
      return null;
    }
    return destination.slice(index + 1, closing);
  }

  const start = index;
  while (index < destination.length && !/\s/.test(destination[index])) {
    index += 1;
  }
  if (index <= start) {
    return null;
  }

  return destination.slice(start, index);
};

export const extractMarkdownImageReferences = (
  markdown: string,
  options: ExtractMarkdownImageReferencesOptions = {},
): MarkdownImageReference[] => {
  const { stopAtLineBreakAtTopLevel = false } = options;
  const references: MarkdownImageReference[] = [];
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
      if (stopAtLineBreakAtTopLevel && (char === '\n' || char === '\r') && nestedParentheses === 0) {
        break;
      }
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
    const imageUrl = parseMarkdownImageDestination(destination);
    if (imageUrl) {
      references.push({
        altText: markdown.slice(imageStart + 2, altEnd),
        imageUrl,
      });
    }

    cursor = index + 1;
  }

  return references;
};
