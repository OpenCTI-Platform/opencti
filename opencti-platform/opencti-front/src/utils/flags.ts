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

export const getFlagUrl = (countryCode: string): string => {
  return flagsByCode[countryCode.toLowerCase()] ?? '';
};
