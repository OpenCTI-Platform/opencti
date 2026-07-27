const flagModules = import.meta.glob<string>(
  '/src/static/images/flags/4x3/*.svg',
  { eager: true, query: '?url', import: 'default' },
);

// Build a lookup map: country code -> asset URL
const flagsByCode: Record<string, string> = {};
for (const [path, url] of Object.entries(flagModules)) {
  const code = path.split('/').pop()?.replace('.svg', '');
  if (code) {
    flagsByCode[code] = url;
  }
}

export const findFlagUrl = (aliases: readonly (string | null | undefined)[] | null | undefined) => (
  (aliases ?? [])
    .filter((alias): alias is string => alias !== undefined && alias !== null && alias.length === 2)
    .map((alias) => flagsByCode[alias.toLowerCase()])
    .filter((url) => url !== undefined)
    .at(0)
);
