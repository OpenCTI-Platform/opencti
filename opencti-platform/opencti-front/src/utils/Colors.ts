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
  Persona: 'observables',

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

  // Restricted
  Restricted: 'restricted',
  Capability: 'restricted',
};

export const itemColor = (
  type: string | null | undefined,
  reversed: boolean = false,
): string => {
  const family = type ? ENTITY_TYPE_TO_FAMILY[type] : null;

  if (family) {
    return COLOR_FAMILIES[family];
  }

  return stringToColour(type, reversed);
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
