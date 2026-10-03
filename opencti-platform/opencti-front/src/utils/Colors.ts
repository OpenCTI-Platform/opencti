import invert from 'invert-color';

export const stringToColour = (str: string | null | undefined, reversed = false) => {
  if (!str) {
    return '#5d4037';
  }
  if (str === 'true') {
    if (reversed) {
      return '#bf360c';
    }
    return '#2e7d32';
  }
  if (str === 'false') {
    if (reversed) {
      return '#2e7d32';
    }
    return '#bf360c';
  }
  let hash = 0;
  for (let i = 0; i < str.length; i += 1) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  let colour = '#';
  for (let i = 0; i < 3; i += 1) {
    const value = (hash >> (i * 8)) & 0xff;
    colour += `00${value.toString(16)}`.substr(-2);
  }
  return colour;
};

const COLOR_FAMILIES = {
  analyse: '#70B23B',
  cases: '#EA80FC',
  events: '#F96C9B',
  observations: '#FF6F42',
  allThreats: '#FF9800',
  arsenal: '#F0B60A',
  techniques: '#D3E157',
  victimology: '#BA88FF',
  locations: '#05ACC1',
  observables: '#84ffff',
  relationships: '#616161',
  restricted: '#424242',
} as const;

const ENTITY_TYPE_TO_FAMILY: Record<string, keyof typeof COLOR_FAMILIES> = {
  // Analyse
  Dashboard: 'analyse',
  Report: 'analyse',
  Grouping: 'analyse',
  'Malware-Analysis': 'analyse',
  Note: 'analyse',
  'External-Reference': 'analyse',
  Investigation: 'analyse',

  // Cases
  'Case-Incident': 'cases',
  'Case-Rfi': 'cases',
  'Case-Rft': 'cases',
  Task: 'cases',
  'Case-Feedback': 'cases',

  // Events
  Incident: 'events',
  Sighting: 'events',
  'Observed-Data': 'events',

  // Observations
  Observable: 'observations',
  Artifact: 'observations',
  Indicator: 'observations',
  Infrastructure: 'observations',
  Opinion: 'observations',

  // All Threats
  'Threat-Actor-Group': 'allThreats',
  'Threat-Actor': 'allThreats',
  'Threat-Actor-Individual': 'allThreats',
  'Intrusion-Set': 'allThreats',
  Campaign: 'allThreats',

  // Arsenal
  Malware: 'arsenal',
  Variant: 'arsenal',
  Channel: 'arsenal',
  Tool: 'arsenal',
  Vulnerability: 'arsenal',
  Session: 'arsenal',
  SecurityPlatform: 'arsenal',

  // Techniques
  'Attack-Pattern': 'techniques',
  Narrative: 'techniques',
  'Course-Of-Action': 'techniques',
  'Data-Component': 'techniques',
  'Data-Source': 'techniques',
  Language: 'techniques',

  // Victimology
  Sector: 'victimology',
  Event: 'victimology',
  Organization: 'victimology',
  System: 'victimology',
  Individual: 'victimology',
  User: 'victimology',
  Group: 'victimology',

  // Locations
  Region: 'locations',
  Country: 'locations',
  'Administrative-Area': 'locations',
  City: 'locations',
  Position: 'locations',

  // Observables (Cyber Observables)
  'Stix-Cyber-Observable': 'observables',
  'Autonomous-System': 'observables',
  Directory: 'observables',
  'Domain-Name': 'observables',
  'Email-Addr': 'observables',
  'Email-Message': 'observables',
  'Email-Mime-Part-Type': 'observables',
  StixFile: 'observables',
  'X509-Certificate': 'observables',
  'AI-Prompt': 'observables',
  'IPv4-Addr': 'observables',
  'IPv6-Addr': 'observables',
  'Mac-Addr': 'observables',
  Mutex: 'observables',
  'Network-Traffic': 'observables',
  Process: 'observables',
  Software: 'observables',
  Url: 'observables',
  'User-Account': 'observables',
  'Windows-Registry-Key': 'observables',
  'Windows-Registry-Value-Type': 'observables',
  'Cryptographic-Key': 'observables',
  'Cryptocurrency-Wallet': 'observables',
  Text: 'observables',
  'User-Agent': 'observables',
  'Bank-Account': 'observables',
  Credential: 'observables',
  'Tracking-Number': 'observables',
  'Phone-Number': 'observables',
  'Payment-Card': 'observables',
  'Media-Content': 'observables',
  'SSH-Key': 'observables',
  Persona: 'observables',
  IMEI: 'observables',
  IMSI: 'observables',
  ICCID: 'observables',

  // Relationships
  'Stix-Core-Relationship': 'relationships',
  Relationship: 'relationships',
  'stix-core-relationship': 'relationships',
  targets: 'relationships',
  uses: 'relationships',
  'located-at': 'relationships',
  'related-to': 'relationships',
  'technology-from': 'relationships',
  'technology-to': 'relationships',
  technology: 'relationships',
  'transferred-to': 'relationships',
  demonstrates: 'relationships',
  mitigates: 'relationships',
  impersonates: 'relationships',
  indicates: 'relationships',
  'comes-after': 'relationships',
  'attributed-to': 'relationships',
  'variant-of': 'relationships',
  'part-of': 'relationships',
  'employed-by': 'relationships',
  'resides-in': 'relationships',
  'citizen-of': 'relationships',
  'national-of': 'relationships',
  drops: 'relationships',
  delivers: 'relationships',
  compromises: 'relationships',
  'belongs-to': 'relationships',
  'based-on': 'relationships',
  'communicates-with': 'relationships',
  amplifies: 'relationships',
  'analyses-of': 'relationships',
  'authored-by': 'relationships',
  'beacons-to': 'relationships',
  characterizes: 'relationships',
  'consists-of': 'relationships',
  'interpreted-by': 'relationships',
  controls: 'relationships',
  'cooperates-with': 'relationships',
  'derived-from': 'relationships',
  downloads: 'relationships',
  has: 'relationships',
  bcc: 'relationships',
  cc: 'relationships',
  'obs_belongs-to': 'relationships',
  owns: 'relationships',
  dst: 'relationships',
  from: 'relationships',
  hosts: 'relationships',
  image: 'relationships',
  publishes: 'relationships',
  'duplicate-of': 'relationships',
  obs_content: 'relationships',
  'service-dll': 'relationships',
  'dynamic-analyses-of': 'relationships',
  contains: 'relationships',
  'exfiltrates-to': 'relationships',
  exploits: 'relationships',
  investigates: 'relationships',
  'originates-from': 'relationships',
  'participates-in': 'relationships',
  'body-multipart': 'relationships',
  'body-raw': 'relationships',
  child: 'relationships',
  'creator-user': 'relationships',
  detects: 'relationships',
  'dst-payload': 'relationships',
  'encapsulated-by': 'relationships',
  encapsulates: 'relationships',
  'opened-connection': 'relationships',
  'operating-system': 'relationships',
  parent: 'relationships',
  'parent-directory': 'relationships',
  'raw-email': 'relationships',
  'src-payload': 'relationships',
  remediates: 'relationships',
  'resolves-to': 'relationships',
  'obs_resolves-to': 'relationships',
  'revoked-by': 'relationships',
  sample: 'relationships',
  sender: 'relationships',
  src: 'relationships',
  to: 'relationships',
  values: 'relationships',
  'static-analyses-of': 'relationships',
  'subnarrative-of': 'relationships',
  'subtechnique-of': 'relationships',
  numberOfConnectedElement: 'relationships',
  'known-as': 'relationships',
  'reports-to': 'relationships',
  supports: 'relationships',
  'has-covered': 'relationships',

  // Restricted
  Restricted: 'restricted',
  Capability: 'restricted',
};

export const itemColor = (
  type: string | null | undefined,
  reversed: boolean = false,
): string => {
  const normalizedType = (type === 'Dynamic from context' || type === 'Dynamic from draft')
    ? 'Dynamic options'
    : type;
  const family = normalizedType ? ENTITY_TYPE_TO_FAMILY[normalizedType] : null;

  // SCO colors are generated based on their type to differentiate them
  if (normalizedType && family === 'observables') {
    return stringToColour(normalizedType);
  }

  if (family) {
    return COLOR_FAMILIES[family];
  }

  return stringToColour(normalizedType, reversed);
};

export type ChipEntityValue
  = | 'analyses' | 'cases' | 'events' | 'observations' | 'all-threats'
    | 'arsenal' | 'techniques' | 'victimology' | 'location';

const FAMILY_TO_CHIP_ENTITY: Partial<Record<keyof typeof COLOR_FAMILIES, ChipEntityValue>> = {
  analyse: 'analyses',
  cases: 'cases',
  events: 'events',
  observations: 'observations',
  observables: 'observations',
  allThreats: 'all-threats',
  arsenal: 'arsenal',
  techniques: 'techniques',
  victimology: 'victimology',
  locations: 'location',
};

export const itemEntity = (type: string | null | undefined): ChipEntityValue | undefined => {
  if (!type) return undefined;
  const family = ENTITY_TYPE_TO_FAMILY[type];
  return family ? FAMILY_TO_CHIP_ENTITY[family] : undefined;
};

const toLab = (rgb: [number, number, number]): [number, number, number] => {
  const inv = (v: number) => {
    const x = v / 255;
    return x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
  };
  const [r, g, b] = rgb.map(inv);
  const f = (t: number) => (t > 0.008856 ? t ** (1 / 3) : 7.787 * t + 16 / 116);
  const fx = f((r * 0.4124 + g * 0.3576 + b * 0.1805) / 0.95047);
  const fy = f(r * 0.2126 + g * 0.7152 + b * 0.0722);
  const fz = f((r * 0.0193 + g * 0.1192 + b * 0.9505) / 1.08883);
  return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
};

const parseHex = (hex: string): [number, number, number] | null => {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex.trim());
  if (!m) return null;
  const n = parseInt(m[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
};

export const MARKING_MIN_DELTA_E = 10;

export const isWashVisibleOn = (
  color: string | null | undefined,
  surface: string | null | undefined,
  alpha = 0.2,
): boolean => {
  if (!color || !surface) return true;
  const c = parseHex(color);
  const s = parseHex(surface);
  // Anything this cannot read is left exactly as it renders today.
  if (!c || !s) return true;
  const washed = c.map((v, i) => Math.round(v * alpha + s[i] * (1 - alpha))) as [number, number, number];
  const a = toLab(washed);
  const b = toLab(s);
  const dE = Math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2);
  return dE >= MARKING_MIN_DELTA_E;
};

// The `#` is optional on the way in: the Chip's own parser accepts a bare `70d907`,
// so a label already stored that way must keep rendering.
const HEX_COLOR_REGEX = /^#?([A-Fa-f0-9]{8}|[A-Fa-f0-9]{6}|[A-Fa-f0-9]{4}|[A-Fa-f0-9]{3})$/;
const CSS_NUMBER_SOURCE = '[+-]?(?:\\d+(?:\\.\\d*)?|\\.\\d+)';
const RGB_COLOR_REGEX = new RegExp(
  `^rgba?\\(\\s*(${CSS_NUMBER_SOURCE}%?)\\s*[ ,]\\s*(${CSS_NUMBER_SOURCE}%?)\\s*[ ,]\\s*(${CSS_NUMBER_SOURCE}%?)(?:\\s*[,/]\\s*(${CSS_NUMBER_SOURCE}%?))?\\s*\\)$`,
  'i',
);
const HSL_COLOR_REGEX = new RegExp(
  `^hsla?\\(\\s*(${CSS_NUMBER_SOURCE})(?:deg)?\\s*[ ,]\\s*(${CSS_NUMBER_SOURCE})%\\s*[ ,]\\s*(${CSS_NUMBER_SOURCE})%(?:\\s*[,/]\\s*(${CSS_NUMBER_SOURCE}%?))?\\s*\\)$`,
  'i',
);

const toHexPair = (value: number): string | null => {
  if (!Number.isFinite(value)) {
    return null;
  }
  return Math.round(Math.min(255, Math.max(0, value)))
    .toString(16)
    .padStart(2, '0');
};

const rgbToHexColor = (r: number, g: number, b: number): string | null => {
  const red = toHexPair(r);
  const green = toHexPair(g);
  const blue = toHexPair(b);
  return red && green && blue ? `#${red}${green}${blue}` : null;
};

const parseFiniteNumber = (raw: string): number | null => {
  const value = Number.parseFloat(raw);
  return Number.isFinite(value) ? value : null;
};

const rgbChannel = (raw: string): number | null => {
  const value = parseFiniteNumber(raw);
  if (value === null) {
    return null;
  }
  return raw.trim().endsWith('%') ? (value / 100) * 255 : value;
};

const hslToHexColor = (h: number, s: number, l: number): string | null => {
  if (!Number.isFinite(h) || !Number.isFinite(s) || !Number.isFinite(l)) {
    return null;
  }
  const saturation = Math.min(1, Math.max(0, s / 100));
  const lightness = Math.min(1, Math.max(0, l / 100));
  const chroma = (1 - Math.abs(2 * lightness - 1)) * saturation;
  const sector = (((h % 360) + 360) % 360) / 60;
  const second = chroma * (1 - Math.abs((sector % 2) - 1));
  const [r, g, b] = [
    [chroma, second, 0],
    [second, chroma, 0],
    [0, chroma, second],
    [0, second, chroma],
    [second, 0, chroma],
    [chroma, 0, second],
  ][Math.floor(sector) % 6];
  const offset = lightness - chroma / 2;
  return rgbToHexColor((r + offset) * 255, (g + offset) * 255, (b + offset) * 255);
};

const normalizeHexColor = (value: string): string | null => {
  const match = HEX_COLOR_REGEX.exec(value.trim());
  if (!match) {
    return null;
  }
  const digits = match[1];
  if (digits.length === 3 || digits.length === 4) {
    const [r, g, b] = digits;
    return `#${r}${r}${g}${g}${b}${b}`.toLowerCase();
  }
  return `#${digits.slice(0, 6)}`.toLowerCase();
};

const parseCanvasColor = (value: string): string | null => {
  const normalizedHex = normalizeHexColor(value);
  if (normalizedHex) {
    return normalizedHex;
  }
  const rgbMatch = RGB_COLOR_REGEX.exec(value.trim());
  if (rgbMatch) {
    const red = rgbChannel(rgbMatch[1]);
    const green = rgbChannel(rgbMatch[2]);
    const blue = rgbChannel(rgbMatch[3]);
    if (red === null || green === null || blue === null) {
      return null;
    }
    if (rgbMatch[4] !== undefined && parseFiniteNumber(rgbMatch[4]) === null) {
      return null;
    }
    return rgbToHexColor(red, green, blue);
  }
  const hslMatch = HSL_COLOR_REGEX.exec(value.trim());
  if (hslMatch) {
    const hue = parseFiniteNumber(hslMatch[1]);
    const saturation = parseFiniteNumber(hslMatch[2]);
    const lightness = parseFiniteNumber(hslMatch[3]);
    if (hue === null || saturation === null || lightness === null) {
      return null;
    }
    if (hslMatch[4] !== undefined && parseFiniteNumber(hslMatch[4]) === null) {
      return null;
    }
    return hslToHexColor(hue, saturation, lightness);
  }
  return null;
};

let canvasContext: CanvasRenderingContext2D | null | undefined;
let canvasGetContext: typeof HTMLCanvasElement.prototype.getContext | null = null;

const getCanvasContext = (): CanvasRenderingContext2D | null => {
  if (typeof document === 'undefined') {
    return null;
  }
  try {
    const getContext = HTMLCanvasElement.prototype.getContext;
    if (canvasContext !== undefined && canvasGetContext === getContext) {
      return canvasContext;
    }
    const context = document.createElement('canvas').getContext('2d');
    canvasGetContext = getContext;
    canvasContext = context;
    return context;
  } catch {
    canvasGetContext = null;
    canvasContext = null;
    return null;
  }
};

const CANVAS_SENTINELS = ['#010203', '#040506'];

const normalizeCanvasColor = (color: string): string | null => {
  const context = getCanvasContext();
  if (!context) {
    return null;
  }
  try {
    for (const sentinel of CANVAS_SENTINELS) {
      context.fillStyle = sentinel;
      context.fillStyle = color;
      const parsed = context.fillStyle;
      if (parsed !== sentinel) {
        return parseCanvasColor(parsed);
      }
    }
    return null;
  } catch {
    return null;
  }
};

export const normalizeLabelColor = (color?: string | null): string | null => {
  if (!color) {
    return null;
  }
  const trimmed = color.trim();
  if (!trimmed) {
    return null;
  }
  return normalizeHexColor(trimmed) ?? normalizeCanvasColor(trimmed);
};

export const hexToRGB = (hex?: string, transp: number = 0.1) => {
  if (!hex) return `rgb(${50}, ${50}, ${50}, ${transp})`;
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgb(${r}, ${g}, ${b}, ${transp})`;
};

const numberToHex = (c: number) => {
  const hex = c.toString(16);
  return hex.length === 1 ? `0${hex}` : hex;
};
const rgbToHex = (r: number, g: number, b: number) => {
  return `#${numberToHex(r)}${numberToHex(g)}${numberToHex(b)}`;
};

const generateGreenToRedColor = (n: number) => {
  const red = (n > 50 ? 1 - 2 * ((n - 50) / 100.0) : 1.0) * 255;
  const green = (n > 50 ? 1.0 : (2 * n) / 100.0) * 255;
  const blue = 50;
  return rgbToHex(Math.round(red), Math.round(green), Math.round(blue));
};

export const generateGreenToRedColors = (size: number) => {
  const fact = 100 / size;
  const ns = Array.from(Array(size).keys()).map((idx) => idx * fact);
  return ns.map((n) => generateGreenToRedColor(n));
};

export const parseRGBtoHex = (rgb: string) => {
  const [r, g, b] = rgb.replace(/[^\d,]/g, '').split(',');
  return rgbToHex(parseInt(r, 10), parseInt(g, 10), parseInt(b, 10));
};

const adjustColor = (color: string, amount: number = 1) => {
  return `#${color
    .replace(/^#/, '')
    .replace(/../g, (c) => `0${Math.min(255, Math.max(0, parseInt(c, 16) + amount)).toString(
      16,
    )}`.substr(-2))}`;
};

export const isColorCloseToWhite = (hex: string, threshold: number = 0.9) => {
  if (!hex) return false;
  const c = hex.replace('#', '');
  const r = parseInt(c.substr(0, 2), 16);
  const g = parseInt(c.substr(2, 2), 16);
  const b = parseInt(c.substr(4, 2), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance >= threshold; // filter on too white colors
};

export const generateBannerMessageColors = (color: string) => {
  let messageColor;
  if (color && /^#[0-9A-F]{6}$/i.test(color)) {
    messageColor = hexToRGB(adjustColor(color, 50), 0.9);
  }
  return {
    backgroundColor: messageColor ?? '#ffecb3',
    borderLeft: `8px solid ${messageColor ? color : '#ffc107'}`,
    color: messageColor ? invert(color, true) : '#663c00',
  };
};
