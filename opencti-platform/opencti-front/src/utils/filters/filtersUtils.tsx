export const FiltersVariant = {
  list: 'list',
  dialog: 'dialog',
};

export type BackendFilters = {
  key: string | string[];
  values: string[];
  operator?: string;
  filterMode?: string;
}[];

export const onlyGroupOrganization = ['x_opencti_workflow_id'];
export const directFilters = [
  'is_read',
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
  'trigger_type',
  'instance_trigger',
];
export const inlineFilters = [
  'is_read',
  'trigger_type',
  'instance_trigger',
];
// filters that can have 'eq' or 'not_eq' operator
export const EqFilters = [
  'labelledBy',
  'createdBy',
  'markedBy',
  'entity_type',
  'x_opencti_workflow_id',
  'malware_types',
  'incident_type',
  'context',
  'pattern_type',
  'indicator_types',
  'report_types',
  'note_types',
  'channel_types',
  'event_types',
  'sightedBy',
  'relationship_type',
  'creator',
  'x_opencti_negative',
  'source',
  'objectContains',
  'indicates',
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
];
// filters that targets entities instances
export const entityFilters = [
  'elementId',
  'elementId_not_eq',
  'fromId',
  'toId',
  'createdBy',
  'createdBy_not_eq',
  'objectContains',
  'objectContains_not_eq',
  'indicates',
  'indicates_not_eq',
];

export const isUniqFilter = (key: string) => uniqFilters.includes(key)
  || key.endsWith('start_date')
  || key.endsWith('end_date');
