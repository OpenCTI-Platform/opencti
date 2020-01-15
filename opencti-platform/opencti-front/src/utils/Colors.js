/* eslint-disable no-bitwise */
export const stringToColour = (str) => {
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

export const itemColor = (type, dark) => {
  switch (type) {
    case 'sector':
      if (dark) {
        return '#0d47a1';
      }
      return '#2196f3';
    case 'threat-actor':
      if (dark) {
        return '#880e4f';
      }
      return '#e91e63';
    case 'intrusion-set':
      if (dark) {
        return '#bf360c';
      }
      return '#ff5722';
    case 'campaign':
      if (dark) {
        return '#4a148c';
      }
      return '#9c27b0';
    case 'incident':
      if (dark) {
        return '#f44336';
      }
      return '#b71c1c';
    case 'user':
      if (dark) {
        return '#006064';
      }
      return '#00BCD4';
    case 'organization':
      if (dark) {
        return '#01579b';
      }
      return '#03A9F4';
    case 'city':
      if (dark) {
        return '#004d40';
      }
      return '#009688';
    case 'country':
      if (dark) {
        return '#1a237e';
      }
      return '#3f51b5';
    case 'region':
      if (dark) {
        return '#33691e';
      }
      return '#689f38';
    case 'attack-pattern':
      if (dark) {
        return '#827717';
      }
      return '#cddc39';
    case 'malware':
      if (dark) {
        return '#e65100';
      }
      return '#ff9800';
    case 'tool':
      if (dark) {
        return '#1b5e20';
      }
      return '#4caf50';
    case 'vulnerability':
      if (dark) {
        return '#5d4037';
      }
      return '#795548';
    case 'indicator':
      if (dark) {
        return '#ff6f00';
      }
      return '#ffc107';
    case 'stix-relation':
    case 'stix_relation':
    case 'targets':
    case 'uses':
    case 'related-to':
    case 'mitigates':
    case 'impersonates':
    case 'indicates':
    case 'comes-after':
    case 'attributed-to':
    case 'variant-of':
    case 'localization':
    case 'gathering':
    case 'drops':
      if (dark) {
        return '#616161';
      }
      return '#9e9e9e';
    case 'autonomous-system':
    case 'domain':
    case 'ipv4-addr':
    case 'ipv6-addr':
    case 'url':
    case 'email-address':
    case 'email-subject':
    case 'mutex':
    case 'file':
    case 'file-name':
    case 'file-path':
    case 'file-md5':
    case 'file-sha1':
    case 'file-sha256':
    case 'pdb-path':
    case 'registry-key':
    case 'registry-key-value':
    case 'windows-service-name':
    case 'windows-service-display-name':
    case 'windows-scheduled-task':
    case 'x509-certificate-issuer':
    case 'x509-certificate-serial-number':
      if (dark) {
        return '#37474f';
      }
      return stringToColour(type);
    default:
      return stringToColour(type);
  }
};
