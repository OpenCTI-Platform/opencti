export const FiltersVariant = {
  list: 'list',
  dialog: 'dialog',
};

export const onlyGroupOrganization = ['x_opencti_workflow_id'];
export const directFilters = [
  'report_types',
  'channel_types',
  'x_opencti_detection',
  'sightedBy',
  'container_type',
  'toSightingId',
  'x_opencti_negative',
  'fromId',
  'toId',
  'elementId',
  'note_types',
  'context',
];
const uniqFilters = [
  'revoked',
  'x_opencti_detection',
  'x_opencti_base_score_gt',
  'x_opencti_base_score_lte',
  'x_opencti_base_score_lte',
  'confidence_gt',
  'confidence_lte',
  'likelihood_gt',
  'likelihood_lte',
  'x_opencti_negative',
  'x_opencti_score_gt',
  'x_opencti_score_lte',
  'toSightingId',
  'basedOn',
  'labelledBy_uneq',
];

export const entityTypes = [
  'Attack-Pattern',
  'Campaign',
  'Note',
  'Observed-Data',
  'Opinion',
  'Report',
  'Course-Of-Action',
  'Individual',
  'Organization',
  'Sector',
  'Indicator',
  'Infrastructure',
  'Intrusion-Set',
  'City',
  'Country',
  'Region',
  'Position',
  'Malware',
  'Threat-Actor',
  'Tool',
  'Vulnerability',
  'Incident',
  'Stix-Cyber-Observable',
  'StixFile',
  'IPv4-Addr',
  'Domain-Name',
  'Email-Addr',
  'Email-Message',
];
export const relationTypes = [
  'Stix-Core-Relationship',
  'indicates',
  'targets',
  'uses',
  'located-at',
];

export const isUniqFilter = (key: string) => uniqFilters.includes(key)
  || key.endsWith('start_date')
  || key.endsWith('end_date');
