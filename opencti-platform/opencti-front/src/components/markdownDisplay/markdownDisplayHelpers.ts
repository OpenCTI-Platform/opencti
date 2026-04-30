export const normalizeMarkdownImageUrl = (
  resolvedUrl: string,
  appBasePath: string,
): string => {
  let normalized = resolvedUrl;

  // Keep local embedded links contextual so backend can resolve them via
  // the current entity route (contains entity id in URL path).
  if (normalized.startsWith('/embedded/')) {
    normalized = normalized.slice(1);
  }

  // /storage/get/* serves as attachment; use /storage/view/* for inline rendering.
  if (normalized.includes('/storage/get/embedded/')) {
    normalized = normalized.replace('/storage/get/embedded/', '/storage/view/embedded/');
  }

  const normalizedBasePath = appBasePath === '/' ? '' : appBasePath;
  if (
    normalizedBasePath
    && normalized.startsWith('/storage/')
    && !normalized.startsWith(`${normalizedBasePath}/storage/`)
  ) {
    normalized = `${normalizedBasePath}${normalized}`;
  }

  return normalized;
};

export const resolveAndNormalizeMarkdownImageUrl = (
  url: string,
  resolveImageUrl: ((url: string) => string | null) | undefined,
  appBasePath: string,
): string | null => {
  const resolved = resolveImageUrl ? resolveImageUrl(url) : url;
  if (!resolved) {
    return null;
  }
  return normalizeMarkdownImageUrl(resolved, appBasePath);
};
