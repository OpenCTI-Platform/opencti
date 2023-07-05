/* eslint-disable no-bitwise */
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
    case 'Attack-Pattern':
      if (dark) {
        return '#727926';
      }
      return '#7f8727';
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
        return '#4a2e7a';
      }
      return '#5c418a';
    case 'Case-Feedback':
      if (dark) {
        return '#107a6e';
      }
      return '#44a49d';
    case 'Task':
      if (dark) {
        return '#303f9f';
      }
      return '#3f51b5';
    case 'Campaign':
      if (dark) {
        return '#4a148c';
      }
      return '#9c27b0';
    case 'Note':
      if (dark) {
        return '#43a047';
      }
      return '#2e7d32';
    case 'Observed-Data':
      if (dark) {
        return '#00838f';
      }
      return '#00acc1';
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
      return '#9ccc65';
    case 'Course-Of-Action':
      if (dark) {
        return '#558b2f';
      }
      return '#8bc34a';
    case 'Individual':
    case 'User':
      if (dark) {
        return '#006064';
      }
      return '#00BCD4';
    case 'Group':
      if (dark) {
        return '#006064';
      }
      return '#00BCD4';
    case 'Organization':
      if (dark) {
        return '#01579b';
      }
      return '#03A9F4';
    case 'Sector':
      if (dark) {
        return '#0d47a1';
      }
      return '#2196f3';
    case 'System':
      if (dark) {
        return '#64dd17';
      }
      return '#76ff03';
    case 'Event':
      if (dark) {
        return '#00695c';
      }
      return '#26a69a';
    case 'Indicator':
      if (dark) {
        return '#ff6f00';
      }
      return '#ffc107';
    case 'Infrastructure':
      if (dark) {
        return '#512da8';
      }
      return '#651fff';
    case 'Intrusion-Set':
      if (dark) {
        return '#bf360c';
      }
      return '#ff5722';
    case 'City':
      if (dark) {
        return '#004d40';
      }
      return '#009688';
    case 'Country':
      if (dark) {
        return '#1a237e';
      }
      return '#3f51b5';
    case 'Region':
      if (dark) {
        return '#33691e';
      }
      return '#689f38';
    case 'Administrative-Area':
      if (dark) {
        return '#fbc02d';
      }
      return '#ffeb3b';
    case 'Position':
      if (dark) {
        return '#afb42b';
      }
      return '#d4e157';
    case 'Malware':
      if (dark) {
        return '#e65100';
      }
      return '#ff9800';
    case 'Malware-Analysis':
      if (dark) {
        return '#00838f';
      }
      return '#00bcd4';
    case 'Theat-Actor-Group':
      if (dark) {
        return '#880e4f';
      }
      return '#e91e63';
    case 'Tool':
      if (dark) {
        return '#1b5e20';
      }
      return '#4caf50';
    case 'Channel':
      if (dark) {
        return '#ad1457';
      }
      return '#ec407a';
    case 'Narrative':
      if (dark) {
        return '#558b2f';
      }
      return '#8bc34a';
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
      return '#b71c1c';
    case 'Stix-Cyber-Observable':
    case 'Autonomous-System':
    case 'Directory':
    case 'Domain-Name':
    case 'Email-Addr':
    case 'Email-Message':
    case 'Email-Mime-Part-Type':
    case 'Artifact':
    case 'StixFile':
    case 'X509-Certificate':
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
    case 'Phone-Number':
    case 'Payment-Card':
    case 'Media-Content':
      if (dark) {
        return '#37474f';
      }
      return stringToColour(type);
    case 'Stix-Core-Relationship':
    case 'Relationship':
    case 'stix-core-relationship':
    case 'targets':
    case 'uses':
    case 'located-at':
    case 'related-to':
    case 'mitigates':
    case 'impersonates':
    case 'indicates':
    case 'comes-after':
    case 'attributed-to':
    case 'variant-of':
    case 'part-of':
    case 'drops':
    case 'delivers':
    case 'compromises':
    case 'belongs-to':
    case 'based-on':
    case 'communicates-with':
    case 'amplifies':
    case 'analysis-of':
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
    case 'dynamic-analysis-of':
    case 'contains':
    case 'exfiltrates-to':
    case 'exploits':
    case 'investigates':
    case 'x_opencti_linked-to':
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
    case 'static-analysis-of':
    case 'subnarrative-of':
    case 'subtechnique-of':
      if (dark) {
        return '#616161';
      }
      return '#9e9e9e';
    default:
      return stringToColour(type, reversed);
  }
};

export const hexToRGB = (hex, transp = 0.1) => {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `rgb(${r}, ${g}, ${b}, ${transp})`;
};
