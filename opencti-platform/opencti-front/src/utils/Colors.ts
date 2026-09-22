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

// The 148 CSS named colours, resolved to the hex the design system's Chip can read.
export const CSS_NAMED_COLORS: Record<string, string> = {
  aliceblue: '#f0f8ff',
  antiquewhite: '#faebd7',
  aqua: '#00ffff',
  aquamarine: '#7fffd4',
  azure: '#f0ffff',
  beige: '#f5f5dc',
  bisque: '#ffe4c4',
  black: '#000000',
  blanchedalmond: '#ffebcd',
  blue: '#0000ff',
  blueviolet: '#8a2be2',
  brown: '#a52a2a',
  burlywood: '#deb887',
  cadetblue: '#5f9ea0',
  chartreuse: '#7fff00',
  chocolate: '#d2691e',
  coral: '#ff7f50',
  cornflowerblue: '#6495ed',
  cornsilk: '#fff8dc',
  crimson: '#dc143c',
  cyan: '#00ffff',
  darkblue: '#00008b',
  darkcyan: '#008b8b',
  darkgoldenrod: '#b8860b',
  darkgray: '#a9a9a9',
  darkgreen: '#006400',
  darkgrey: '#a9a9a9',
  darkkhaki: '#bdb76b',
  darkmagenta: '#8b008b',
  darkolivegreen: '#556b2f',
  darkorange: '#ff8c00',
  darkorchid: '#9932cc',
  darkred: '#8b0000',
  darksalmon: '#e9967a',
  darkseagreen: '#8fbc8f',
  darkslateblue: '#483d8b',
  darkslategray: '#2f4f4f',
  darkslategrey: '#2f4f4f',
  darkturquoise: '#00ced1',
  darkviolet: '#9400d3',
  deeppink: '#ff1493',
  deepskyblue: '#00bfff',
  dimgray: '#696969',
  dimgrey: '#696969',
  dodgerblue: '#1e90ff',
  firebrick: '#b22222',
  floralwhite: '#fffaf0',
  forestgreen: '#228b22',
  fuchsia: '#ff00ff',
  gainsboro: '#dcdcdc',
  ghostwhite: '#f8f8ff',
  gold: '#ffd700',
  goldenrod: '#daa520',
  gray: '#808080',
  green: '#008000',
  greenyellow: '#adff2f',
  grey: '#808080',
  honeydew: '#f0fff0',
  hotpink: '#ff69b4',
  indianred: '#cd5c5c',
  indigo: '#4b0082',
  ivory: '#fffff0',
  khaki: '#f0e68c',
  lavender: '#e6e6fa',
  lavenderblush: '#fff0f5',
  lawngreen: '#7cfc00',
  lemonchiffon: '#fffacd',
  lightblue: '#add8e6',
  lightcoral: '#f08080',
  lightcyan: '#e0ffff',
  lightgoldenrodyellow: '#fafad2',
  lightgray: '#d3d3d3',
  lightgreen: '#90ee90',
  lightgrey: '#d3d3d3',
  lightpink: '#ffb6c1',
  lightsalmon: '#ffa07a',
  lightseagreen: '#20b2aa',
  lightskyblue: '#87cefa',
  lightslategray: '#778899',
  lightslategrey: '#778899',
  lightsteelblue: '#b0c4de',
  lightyellow: '#ffffe0',
  lime: '#00ff00',
  limegreen: '#32cd32',
  linen: '#faf0e6',
  magenta: '#ff00ff',
  maroon: '#800000',
  mediumaquamarine: '#66cdaa',
  mediumblue: '#0000cd',
  mediumorchid: '#ba55d3',
  mediumpurple: '#9370db',
  mediumseagreen: '#3cb371',
  mediumslateblue: '#7b68ee',
  mediumspringgreen: '#00fa9a',
  mediumturquoise: '#48d1cc',
  mediumvioletred: '#c71585',
  midnightblue: '#191970',
  mintcream: '#f5fffa',
  mistyrose: '#ffe4e1',
  moccasin: '#ffe4b5',
  navajowhite: '#ffdead',
  navy: '#000080',
  oldlace: '#fdf5e6',
  olive: '#808000',
  olivedrab: '#6b8e23',
  orange: '#ffa500',
  orangered: '#ff4500',
  orchid: '#da70d6',
  palegoldenrod: '#eee8aa',
  palegreen: '#98fb98',
  paleturquoise: '#afeeee',
  palevioletred: '#db7093',
  papayawhip: '#ffefd5',
  peachpuff: '#ffdab9',
  peru: '#cd853f',
  pink: '#ffc0cb',
  plum: '#dda0dd',
  powderblue: '#b0e0e6',
  purple: '#800080',
  rebeccapurple: '#663399',
  red: '#ff0000',
  rosybrown: '#bc8f8f',
  royalblue: '#4169e1',
  saddlebrown: '#8b4513',
  salmon: '#fa8072',
  sandybrown: '#f4a460',
  seagreen: '#2e8b57',
  seashell: '#fff5ee',
  sienna: '#a0522d',
  silver: '#c0c0c0',
  skyblue: '#87ceeb',
  slateblue: '#6a5acd',
  slategray: '#708090',
  slategrey: '#708090',
  snow: '#fffafa',
  springgreen: '#00ff7f',
  steelblue: '#4682b4',
  tan: '#d2b48c',
  teal: '#008080',
  thistle: '#d8bfd8',
  tomato: '#ff6347',
  turquoise: '#40e0d0',
  violet: '#ee82ee',
  wheat: '#f5deb3',
  white: '#ffffff',
  whitesmoke: '#f5f5f5',
  yellow: '#ffff00',
  yellowgreen: '#9acd32',
};

// The `#` is optional on the way in: the Chip's own parser accepts a bare `70d907`,
// so a label already stored that way must keep rendering.
const HEX_COLOR_REGEX = /^#?([A-Fa-f0-9]{8}|[A-Fa-f0-9]{6}|[A-Fa-f0-9]{4}|[A-Fa-f0-9]{3})$/;
const RGB_COLOR_REGEX = /^rgba?\(\s*([\d.]+%?)\s*[ ,]\s*([\d.]+%?)\s*[ ,]\s*([\d.]+%?)\s*(?:[,/]\s*[\d.]+%?\s*)?\)$/i;
const HSL_COLOR_REGEX = /^hsla?\(\s*([\d.]+)(?:deg)?\s*[ ,]\s*([\d.]+)%\s*[ ,]\s*([\d.]+)%\s*(?:[,/]\s*[\d.]+%?\s*)?\)$/i;

const toHexPair = (value: number) => Math.round(Math.min(255, Math.max(0, value)))
  .toString(16)
  .padStart(2, '0');

const rgbToHexColor = (r: number, g: number, b: number) => `#${toHexPair(r)}${toHexPair(g)}${toHexPair(b)}`;

// `50%` and `128` are both legal for an rgb() channel.
const rgbChannel = (raw: string) => {
  const value = parseFloat(raw);
  return raw.trim().endsWith('%') ? (value / 100) * 255 : value;
};

const hslToHexColor = (h: number, s: number, l: number) => {
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

/**
 * A label colour is free text: the picker lets an admin type anything, and older labels
 * carry whatever was stored at the time. The design system's Chip only reads `#rgb` and
 * `#rrggbb` (`HEX_RE` in its `data-color` helper) and silently falls back to the neutral
 * tone for everything else, which is the mismatch reported in #17238: the picker previews
 * `red`, the rendered label does not.
 *
 * This resolves a stored colour to the one form the Chip can read, or null when nothing
 * sensible can be made of it, in which case the caller lets the Chip fall back on purpose.
 * An alpha channel is dropped rather than forwarded: the Chip rejects `#rgba`/`#rrggbbaa`
 * by design, because such a value would multiply into its own bounded wash.
 */
export const normalizeLabelColor = (color?: string | null): string | null => {
  if (!color) {
    return null;
  }
  const trimmed = color.trim();
  if (!trimmed) {
    return null;
  }
  const hexMatch = HEX_COLOR_REGEX.exec(trimmed);
  if (hexMatch) {
    const digits = hexMatch[1];
    if (digits.length === 3 || digits.length === 4) {
      const [r, g, b] = digits;
      return `#${r}${r}${g}${g}${b}${b}`.toLowerCase();
    }
    return `#${digits.slice(0, 6)}`.toLowerCase();
  }
  const rgbMatch = RGB_COLOR_REGEX.exec(trimmed);
  if (rgbMatch) {
    return rgbToHexColor(rgbChannel(rgbMatch[1]), rgbChannel(rgbMatch[2]), rgbChannel(rgbMatch[3]));
  }
  const hslMatch = HSL_COLOR_REGEX.exec(trimmed);
  if (hslMatch) {
    return hslToHexColor(parseFloat(hslMatch[1]), parseFloat(hslMatch[2]), parseFloat(hslMatch[3]));
  }
  return CSS_NAMED_COLORS[trimmed.toLowerCase()] ?? null;
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
