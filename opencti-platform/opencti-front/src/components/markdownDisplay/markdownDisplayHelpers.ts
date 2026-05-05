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
