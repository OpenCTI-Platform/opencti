// Catalogs offered by the configuration screen of the intelligence requirements proof of concept.

export const IR_ENTITY_TYPES = [
  'Attack-Pattern', 'Campaign', 'Channel', 'Course-Of-Action', 'Event', 'Incident', 'Indicator', 'Infrastructure',
  'Intrusion-Set', 'Malware', 'Narrative', 'Note', 'Report', 'Grouping', 'Threat-Actor-Group', 'Threat-Actor-Individual',
  'Tool', 'Vulnerability', 'Software', 'System', 'Organization', 'Individual', 'Sector', 'Country', 'Region', 'City',
  'Domain-Name', 'IPv4-Addr', 'Url', 'StixFile',
];

export const IR_RELATIONSHIP_TYPES = [
  'uses', 'targets', 'exploits', 'indicates', 'variant-of', 'related-to', 'attributed-to', 'has', 'delivers', 'drops',
  'located-at', 'part-of', 'communicates-with', 'compromises', 'originates-from', 'impersonates', 'mitigates',
  'remediates', 'belongs-to', 'derived-from', 'authored-by', 'hosts', 'owns', 'beacons-to', 'downloads',
];

export const IR_KEYWORD_FIELDS = ['name', 'description', 'content'];
