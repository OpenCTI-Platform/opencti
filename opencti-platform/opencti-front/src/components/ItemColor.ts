import { useTheme } from '@mui/material';
import useAuth from '../utils/hooks/useAuth';
import { stringToColour } from '../utils/Colors';

/**
 * itemColor function that uses hooks to determine monochrome label and theme mode
 * Can only be used in functional components
 * @param type type of the entity
 * @param reversed is the relation reversed
 * @returns color hexcode
 */
const itemColor = (type: string, reversed = false) => {
  const { me: { monochrome_labels } } = useAuth();
  const theme = useTheme();
  const dark = theme.palette.mode === 'dark';

  if (monochrome_labels) {
    switch (type) {
      // Analyses
      case 'Report':
      case 'Grouping':
      case 'Malware-Analysis':
      case 'Note':
      case 'External-Reference':
      case 'Opinion':
        return dark ? '#679f38' : '#006064';
      // Cases
      case 'Case-Incident':
      case 'Case-Rfi':
      case 'Case-Rft':
      case 'Task':
      case 'Case-Feedback':
        return dark ? '#ea80fc' : '#d81b60';
      // Events
      case 'Incident':
      case 'Sighting':
      case 'Observed-Data':
        return dark ? '#ec407a' : '#880d4f';
      // Observations
      case 'Stix-Cyber-Observable':
      case 'Autonomous-System':
      case 'Directory':
      case 'Domain-Name':
      case 'Email-Addr':
      case 'Email-Message':
      case 'Email-Mime-Part-Type':
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
      case 'Credential':
      case 'Tracking-Number':
      case 'Phone-Number':
      case 'Payment-Card':
      case 'Media-Content':
      case 'Persona':
      case 'Artifact':
      case 'Indicator':
      case 'Infrastructure':
        return '#fe5622';
      // Threats
      case 'Threat-Actor-Group':
      case 'Threat-Actor-Individual':
      case 'Intrusion-Set':
      case 'Campaign':
        return dark ? '#ff9800' : '#d68100';
      // Arsenal
      case 'Malware':
      case 'Channel':
      case 'Tool':
      case 'Vulnerability':
        return dark ? '#ffc108' : '#b59005';
      // Techniques
      case 'Attack-Pattern':
      case 'Narrative':
      case 'Course-Of-Action':
      case 'Data-Component':
      case 'Data-Source':
        return dark ? '#d4e157' : '#817717';
      // Entities
      case 'Sector':
      case 'Event':
      case 'Organization':
      case 'System':
      case 'Individual':
      case 'User':
        return dark ? '#9447ff' : '#512da8';
      // Locations
      case 'Region':
      case 'Country':
      case 'Administrative-Area':
      case 'City':
      case 'Position':
        return dark ? '#00acc1' : '#0675be';
      // Misc
      case 'Language':
        return dark ? '#afb42b' : '#d4e157';
      case 'Dashboard':
      case 'Investigation':
        return dark ? '#689f38' : '#33691e';
      case 'Session':
        return dark ? '#5d4037' : '#795548';
      // Relationships
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
        return dark ? '#616161' : '#9e9e9e';
      default:
        return stringToColour(type, reversed);
    }
  }

  switch (type) {
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
      if (dark) {
        return '#616161';
      }
      return '#9e9e9e';
    default:
      return stringToColour(type, reversed);
  }
};

export default itemColor;
