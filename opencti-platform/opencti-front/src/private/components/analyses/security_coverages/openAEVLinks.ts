export interface OpenAEVLink {
  url: string;
  label: string;
  host: string;
}

const hostOf = (url: string): string => {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
};

// One entry per distinct OpenAEV URL: the coverage results of one scenario carry the same link.
// The label is the result name, else the host, so a chooser never shows a raw URL glued to a description.
export const distinctOpenAEVLinks = (
  results: ReadonlyArray<{ readonly name?: string | null; readonly external_uri?: string | null }> | null | undefined,
): OpenAEVLink[] => {
  const links = new Map<string, OpenAEVLink>();
  (results ?? []).forEach((result) => {
    const url = result.external_uri?.trim();
    if (!url || links.has(url)) {
      return;
    }
    const host = hostOf(url);
    links.set(url, { url, host, label: result.name?.trim() || host });
  });
  return Array.from(links.values());
};
