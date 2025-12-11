/* eslint-disable no-bitwise */
import invert from 'invert-color';

export const stringToColour = (str, reversed = false) => {
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
/* eslint-enable no-bitwise */

export const itemColor = (type, dark = false, reversed = false) => {
  switch (type) {
    case 'Restricted':
      if (dark) {
        return '#424242';
      }
      return '#B0B0B0';
    case 'Attack-Pattern':
      if (dark) {
        return '#d4e157';
      }
      return '#827717';
    case 'Case-Incident':
      if (dark) {
        return '#ad1457';
      }
      return '#ec407a';
    case 'Case-Rfi':
      if (dark) {
        return '#0c5c98';
      }
      return '#3880b7';
    case 'Case-Rft':
      if (dark) {
        return '#ea80fc';
      }
      return '#8e24aa';
    case 'Case-Feedback':
      if (dark) {
        return '#00acc1';
      }
      return '#006064';
    case 'Task':
      if (dark) {
        return '#304ffe';
      }
      return '#283593';
    case 'Campaign':
      if (dark) {
        return '#8e24aa';
      }
      return '#ea80fc';
    case 'Note':
      if (dark) {
        return '#33691e';
      }
      return '#689f38';
    case 'Observed-Data':
      if (dark) {
        return '#00acc1';
      }
      return '#006064';
    case 'Opinion':
      if (dark) {
        return '#1565c0';
      }
      return '#1976d2';
    case 'Report':
      if (dark) {
        return '#4a148c';
      }
      return '#9c27b0';
    case 'Grouping':
      if (dark) {
        return '#689f38';
      }
      return '#8bc34a';
    case 'Course-Of-Action':
      if (dark) {
        return '#8bc34a';
      }
      return '#689f38';
    case 'Individual':
    case 'User':
      if (dark) {
        return '#9c27b0';
      }
      return '#4a148c';
    case 'Group':
      if (dark) {
        return '#006064';
      }
      return '#00bcd4';
    case 'Capability':
      if (dark) {
        return '#424242';
      }
      return '#757575';
    case 'Organization':
      if (dark) {
        return '#3880b7';
      }
      return '#0c5c98';
    case 'Sector':
      if (dark) {
        return '#0d47a1';
      }
      return '#2196f3';
    case 'System':
      if (dark) {
        return '#8bc34a';
      }
      return '#689f38';
    case 'Event':
      if (dark) {
        return '#00acc1';
      }
      return '#006064';
    case 'Indicator':
      if (dark) {
        return '#ffc107';
      }
      return '#b69007';
    case 'Infrastructure':
      if (dark) {
        return '#512da8';
      }
      return '#651fff';
    case 'Intrusion-Set':
      if (dark) {
        return '#bf360c';
      }
      return '#ff5622';
    case 'City':
      if (dark) {
        return '#00acc1';
      }
      return '#006064';
    case 'Country':
      if (dark) {
        return '#304ffe';
      }
      return '#283593';
    case 'Region':
      if (dark) {
        return '#33691e';
      }
      return '#689f38';
    case 'Administrative-Area':
      if (dark) {
        return '#ffc107';
      }
      return '#b69007';
    case 'Position':
      if (dark) {
        return '#00acc1';
      }
      return '#827717';
    case 'Malware':
      if (dark) {
        return '#ff9800';
      }
      return '#d68100';
    case 'Malware-Analysis':
      if (dark) {
        return '#006064';
      }
      return '#00acc1';
    case 'Threat-Actor':
    case 'Threat-Actor-Group':
      if (dark) {
        return '#880e4f';
      }
      return '#e91e63';
    case 'Threat-Actor-Individual':
      if (dark) {
        return '#4a148c';
      }
      return '#9c27b0';
    case 'SecurityPlatform':
      if (dark) {
        return '#4a148c';
      }
      return '#baff7a';
    case 'Tool':
      if (dark) {
        return '#986937';
      }
      return '#986937';
    case 'Channel':
      if (dark) {
        return '#ad1457';
      }
      return '#ec407a';
    case 'Narrative':
      if (dark) {
        return '#8bc34a';
      }
      return '#689f38';
    case 'Language':
      if (dark) {
        return '#afb42b';
      }
      return '#d4e157';
    case 'Vulnerability':
      if (dark) {
        return '#5d4037';
      }
      return '#795548';
    case 'Incident':
      if (dark) {
        return '#f44336';
      }
      return '#f44336';
    case 'Dashboard':
      if (dark) {
        return '#689f38';
      }
      return '#33691e';
    case 'Investigation':
      if (dark) {
        return '#689f38';
      }
      return '#33691e';
    case 'Session':
      if (dark) {
        return '#5d4037';
      }
      return '#795548';
    case 'Artifact':
      if (dark) {
        return '#f2699c';
      }
      return '#ff4081';
    case 'Stix-Cyber-Observable':
    case 'Autonomous-System':
    case 'Directory':
    case 'Domain-Name':
    case 'Email-Addr':
    case 'Email-Message':
    case 'Email-Mime-Part-Type':
    case 'StixFile':
    case 'X509-Certificate':
    case 'ICCID':
    case 'IMEI':
    case 'IMSI':  
    case 'IPv4-Addr':
    case 'IPv6-Addr':
    case 'Mac-Addr':
    case 'Mutex':
    case 'Network-Traffic':
    case 'Process':
    case 'Software':
    case 'Url':
    case 'User-Account':
    case 'Windows-Registry-Key':
    case 'Windows-Registry-Value-Type':
    case 'Cryptographic-Key':
    case 'Cryptocurrency-Wallet':
    case 'Text':
    case 'User-Agent':
    case 'Bank-Account':
    case 'Credential':
    case 'Tracking-Number':
    case 'Phone-Number':
    case 'Payment-Card':
    case 'Media-Content':
    case 'Persona':
      if (dark) {
        return '#84ffff';
      }
      return stringToColour(type);
    case 'Stix-Core-Relationship':
    case 'Relationship':
    case 'stix-core-relationship':
    case 'targets':
    case 'uses':
    case 'located-at':
    case 'related-to':
    case 'technology-from':
    case 'technology-to':
    case 'technology':
    case 'transferred-to':
    case 'demonstrates':
    case 'mitigates':
    case 'impersonates':
    case 'indicates':
    case 'comes-after':
    case 'attributed-to':
    case 'variant-of':
    case 'part-of':
    case 'employed-by':
    case 'resides-in':
    case 'citizen-of':
    case 'national-of':
    case 'drops':
    case 'delivers':
    case 'compromises':
    case 'belongs-to':
    case 'based-on':
    case 'communicates-with':
    case 'amplifies':
    case 'analyses-of':
    case 'authored-by':
    case 'beacons-to':
    case 'characterizes':
    case 'consists-of':
    case 'controls':
    case 'cooperates-with':
    case 'derived-from':
    case 'downloads':
    case 'has':
    case 'bcc':
    case 'cc':
    case 'obs_belongs-to':
    case 'owns':
    case 'dst':
    case 'from':
    case 'hosts':
    case 'image':
    case 'publishes':
    case 'duplicate-of':
    case 'obs_content':
    case 'service-dll':
    case 'dynamic-analyses-of':
    case 'contains':
    case 'exfiltrates-to':
    case 'exploits':
    case 'investigates':
    case 'originates-from':
    case 'participates-in':
    case 'body-multipart':
    case 'body-raw':
    case 'child':
    case 'creator-user':
    case 'detects':
    case 'dst-payload':
    case 'encapsulated-by':
    case 'encapsulates':
    case 'opened-connection':
    case 'operating-system':
    case 'parent':
    case 'parent-directory':
    case 'raw-email':
    case 'src-payload':
    case 'remediates':
    case 'resolves-to':
    case 'obs_resolves-to':
    case 'revoked-by':
    case 'sample':
    case 'sender':
    case 'src':
    case 'to':
    case 'values':
    case 'static-analyses-of':
    case 'subnarrative-of':
    case 'subtechnique-of':
    case 'numberOfConnectedElement':
    case 'known-as':
    case 'reports-to':
    case 'supports':
      if (dark) {
        return '#616161';
      }
      return '#9e9e9e';
    default:
      return stringToColour(type, reversed);
  }
};

export const hexToRGB = (hex, transp = 0.1) => {
  if (!hex) return `rgb(${50}, ${50}, ${50}, ${transp})`;
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgb(${r}, ${g}, ${b}, ${transp})`;
};

const numberToHex = (c) => {
  const hex = c.toString(16);
  return hex.length === 1 ? `0${hex}` : hex;
};
const rgbToHex = (r, g, b) => {
  return `#${numberToHex(r)}${numberToHex(g)}${numberToHex(b)}`;
};

const generateGreenToRedColor = (n) => {
  const red = (n > 50 ? 1 - 2 * ((n - 50) / 100.0) : 1.0) * 255;
  const green = (n > 50 ? 1.0 : (2 * n) / 100.0) * 255;
  const blue = 50;
  return rgbToHex(Math.round(red), Math.round(green), Math.round(blue));
};

export const generateGreenToRedColors = (size) => {
  const fact = 100 / size;
  const ns = Array.from(Array(size).keys()).map((idx) => idx * fact);
  return ns.map((n) => generateGreenToRedColor(n));
};

export const parseRGBtoHex = (rgb) => {
  const [r, g, b] = rgb.replace(/[^\d,]/g, '').split(',');
  return rgbToHex(parseInt(r, 10), parseInt(g, 10), parseInt(b, 10));
};

const adjustColor = (color, amount = 1) => {
  return `#${color
    .replace(/^#/, '')
    .replace(/../g, (c) => `0${Math.min(255, Math.max(0, parseInt(c, 16) + amount)).toString(
      16,
    )}`.substr(-2))}`;
};

export const isColorCloseToWhite = (hex, threshold = 0.9) => {
  if (!hex) return false;
  const c = hex.replace('#', '');
  const r = parseInt(c.substr(0, 2), 16);
  const g = parseInt(c.substr(2, 2), 16);
  const b = parseInt(c.substr(4, 2), 16);
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  return luminance >= threshold; // filter on too white colors
};

export const generateBannerMessageColors = (color) => {
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
