export const normalizeMarkdownImageUrl = (
  resolvedUrl: string,
  appBasePath: string,
): string => {
  let normalized = resolvedUrl;
  const normalizedBasePath = appBasePath === '/' ? '' : appBasePath;

  // Keep local embedded links contextual so backend can resolve them via
  // the current entity route (contains entity id in URL path).
  if (normalized.startsWith('/embedded/')) {
    normalized = normalized.slice(1);
  }

  if (
    normalizedBasePath
    && normalized.startsWith('/storage/')
    && !normalized.startsWith(`${normalizedBasePath}/storage/`)
  ) {
    normalized = `${normalizedBasePath}${normalized}`;
  }

  return normalized;
};

const resolveContextualEmbeddedImageUrl = (
  url: string,
  currentPathname: string,
): string => {
  const normalizedUrl = url.startsWith('/') ? url.slice(1) : url;
  if (!normalizedUrl.startsWith('embedded/')) {
    return url;
  }

  const normalizedPathname = currentPathname.replace(/\/+$/, '');
  if (!normalizedPathname) {
    return `/${normalizedUrl}`;
  }

  return `${normalizedPathname}/${normalizedUrl}`;
};

const findClosingParen = (source: string, from: number): number => {
  let nestedParentheses = 0;
  let index = from;
  while (index < source.length) {
    const char = source[index];
    if (char === '\\') {
      index += 2;
      continue;
    }
    if (char === '(') nestedParentheses += 1;
    else if (char === ')') {
      if (nestedParentheses === 0) return index;
      nestedParentheses -= 1;
    }
    index += 1;
  }
  return -1;
};

export const normalizeEmbeddedImageDestinations = (markdown: string | null | undefined): string => {
  // - react-markdown does not reliably parse embedded image destinations with raw whitespace.
  // - We wrap and encode only the embedded URL segment so rendering works while preserving markdown titles.
  const source = (markdown ?? '').toString();
  let normalized = '';
  let cursor = 0;

  while (cursor < source.length) {
    const imageStart = source.indexOf('![', cursor);
    if (imageStart < 0) {
      normalized += source.slice(cursor);
      break;
    }

    const altEnd = source.indexOf(']', imageStart + 2);
    if (altEnd < 0 || source[altEnd + 1] !== '(') {
      normalized += source.slice(cursor, imageStart + 2);
      cursor = imageStart + 2;
      continue;
    }

    const destinationStart = altEnd + 2;
    const destinationEnd = findClosingParen(source, destinationStart);
    if (destinationEnd < 0) {
      normalized += source.slice(cursor, imageStart + 2);
      cursor = imageStart + 2;
      continue;
    }

    const destination = source.slice(destinationStart, destinationEnd).trim();
    let imageUrl = destination;
    let titleSuffix = '';

    const trailingQuote = destination[destination.length - 1];
    if (trailingQuote === '"' || trailingQuote === '\'') {
      const openingQuote = destination.lastIndexOf(trailingQuote, destination.length - 2);
      if (openingQuote > 0 && /\s/.test(destination[openingQuote - 1])) {
        const titleContent = destination.slice(openingQuote + 1, destination.length - 1);
        imageUrl = destination.slice(0, openingQuote).trimEnd();
        titleSuffix = ` ${trailingQuote}${titleContent}${trailingQuote}`;
      }
    }

    const isEmbedded = imageUrl.startsWith('embedded/') || imageUrl.startsWith('/embedded/');
    const needsWrapping = isEmbedded && /\s/.test(imageUrl) && !imageUrl.startsWith('<');

    normalized += source.slice(cursor, imageStart);
    if (needsWrapping) {
      normalized += source.slice(imageStart, destinationStart);
      normalized += `<${encodeURI(imageUrl)}>${titleSuffix}`;
      normalized += ')';
    } else {
      normalized += source.slice(imageStart, destinationEnd + 1);
    }

    cursor = destinationEnd + 1;
  }

  return normalized;
};

export const resolveAndNormalizeMarkdownImageUrl = (
  url: string,
  resolveImageUrl: ((url: string) => string | null) | undefined,
  appBasePath: string,
  currentPathname: string,
): string | null => {
  const resolved = resolveImageUrl
    ? resolveImageUrl(url)
    : resolveContextualEmbeddedImageUrl(url, currentPathname);
  if (!resolved) {
    return null;
  }
  return normalizeMarkdownImageUrl(resolved, appBasePath);
};
