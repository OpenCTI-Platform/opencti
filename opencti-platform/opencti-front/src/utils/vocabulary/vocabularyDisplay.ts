// Display helpers of open vocabulary values: the human label a reader sees, and the tooltip without machine suffixes.
// The stored value stays the vocabulary key (AI_AGENT, VERY_HIGH, production); only the screen changes.

// Words kept as written when a key is turned into a label
const ACRONYMS: Record<string, string> = {
  ai: 'AI',
  api: 'API',
  dhcp: 'DHCP',
  dns: 'DNS',
  edr: 'EDR',
  graphql: 'GraphQL',
  hmi: 'HMI',
  iac: 'IaC',
  iam: 'IAM',
  ios: 'iOS',
  iot: 'IoT',
  ispm: 'ISPM',
  llm: 'LLM',
  macos: 'macOS',
  mcp: 'MCP',
  ml: 'ML',
  mgmt: 'management',
  nas: 'NAS',
  ndr: 'NDR',
  ot: 'OT',
  plc: 'PLC',
  rag: 'RAG',
  rtu: 'RTU',
  saas: 'SaaS',
  san: 'SAN',
  scada: 'SCADA',
  siem: 'SIEM',
  soar: 'SOAR',
  vpn: 'VPN',
  xdr: 'XDR',
};

/**
 * Turns a vocabulary key into a sentence-case label: AI_AGENT -> "AI agent", VERY_HIGH -> "Very high",
 * NETWORK_DEVICE -> "Network device", production -> "Production".
 * A key already written as a label (Windows, Linux, MacOS) is returned as it is.
 */
export const humanizeVocabularyKey = (key: string): string => {
  if (!key) return key;
  const isMachineKey = /^[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)*$/.test(key) && (key.includes('_') || key === key.toUpperCase() || key === key.toLowerCase());
  if (!isMachineKey) return key;
  const words = key.split(/[_-]/).filter((w) => w.length > 0).map((word, index) => {
    const lower = word.toLowerCase();
    if (ACRONYMS[lower]) return ACRONYMS[lower];
    return index === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
  });
  const label = words.join(' ');
  return label.charAt(0).toUpperCase() + label.slice(1);
};

/**
 * The label shown for a value: its translation when the catalog holds the humanized label, else the humanized label.
 * translate is the formatter's t_i18n, which answers the id itself when the catalog has no entry.
 */
export const vocabularyValueLabel = (value: string, translate: (message: string) => string): string => {
  return translate(humanizeVocabularyKey(value));
};

// Machine suffixes some descriptions carry for the forms (the subcategory names its category: "(category: AI_TARGET)")
const MACHINE_SUFFIX = /\s*\((?:category): [^)]+\)\s*$/;

export const vocabularyDescriptionForDisplay = (description?: string | null): string | undefined => {
  if (!description) return undefined;
  const text = description.replace(MACHINE_SUFFIX, '').trim();
  return text.length > 0 ? text : undefined;
};

// A colour stored on a vocabulary entry, accepted only as a hex colour (an administrator types it in a free field)
export const vocabularyColor = (color?: string | null): string | undefined => {
  if (!color) return undefined;
  return /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/.test(color.trim()) ? color.trim() : undefined;
};
