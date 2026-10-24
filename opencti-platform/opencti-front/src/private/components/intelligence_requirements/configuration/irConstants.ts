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

export interface IrAttributeDefinition {
  key: string;
  label: string;
  kind: 'bool' | 'number' | 'enum' | 'type';
  operators: string[];
  values?: string[];
}

// Curated OpenCTI filter keys usable on an entity in the stream (they have a STIX tester)
export const IR_ATTRIBUTES: IrAttributeDefinition[] = [
  { key: 'entity_type', label: 'Entity type', kind: 'type', operators: ['eq', 'not_eq'] },
  { key: 'x_opencti_cisa_kev', label: 'CISA KEV', kind: 'bool', operators: ['eq'], values: ['true', 'false'] },
  { key: 'x_opencti_epss_score', label: 'EPSS score', kind: 'number', operators: ['gte', 'lte'] },
  { key: 'x_opencti_epss_percentile', label: 'EPSS percentile', kind: 'number', operators: ['gte', 'lte'] },
  { key: 'x_opencti_cvss_base_score', label: 'CVSS base score', kind: 'number', operators: ['gte', 'lte'] },
  { key: 'x_opencti_cvss_base_severity', label: 'CVSS severity', kind: 'enum', operators: ['eq', 'not_eq'], values: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
  { key: 'x_opencti_ssvc_exploitation', label: 'SSVC exploitation', kind: 'enum', operators: ['eq', 'not_eq'], values: ['none', 'proof_of_concept', 'active'] },
  { key: 'confidence', label: 'Confidence', kind: 'number', operators: ['gte', 'lte'] },
  { key: 'x_opencti_score', label: 'Score', kind: 'number', operators: ['gte', 'lte'] },
];

export const IR_OPERATOR_LABELS: Record<string, string> = { eq: 'is', not_eq: 'is not', gte: '≥', lte: '≤' };
