import type { UpdateStep } from '../dataTableToolBarUpdateSteps';

const typesWithScore = [
  'Malware',
  'Stix-Cyber-Observable',
  'Indicator',
  'Autonomous-System',
  'Directory',
  'Domain-Name',
  'Email-Addr',
  'Email-Message',
  'Email-Mime-Part-Type',
  'StixFile',
  'X509-Certificate',
  'IPv4-Addr',
  'IPv6-Addr',
  'Mac-Addr',
  'Mutex',
  'Network-Traffic',
  'Process',
  'Software',
  'Url',
  'User-Account',
  'Windows-Registry-Key',
  'Windows-Registry-Value-Type',
  'Cryptographic-Key',
  'Cryptocurrency-Wallet',
  'Hostname',
  'Text',
  'Credential',
  'Tracking-Number',
  'User-Agent',
  'Bank-Account',
  'Phone-Number',
  'Payment-Card',
  'Media-Content',
  'Persona',
  'Threat-Actor-Group',
  'Intrusion-Set',
  'Event',
];
const typesWithSeverity = ['Case-Incident', 'Case-Rft', 'Case-Rfi'];
const typesWithPriority = ['Case-Incident', 'Case-Rft', 'Case-Rfi'];
const typesWithAssignee = ['Case-Incident', 'Case-Rft', 'Case-Rfi', 'Report'];
const typesWithParticipant = ['Case-Incident', 'Case-Rft', 'Case-Rfi', 'Report'];
const typesWithIncidentResponseType = ['Case-Incident'];
const typesWithRfiTypes = ['Case-Rfi'];
const typesWithRftTypes = ['Case-Rft'];
const typesWithDetection = ['Indicator'];
const typesWithKillChains = ['Indicator'];
const typesWithIndicatorTypes = ['Indicator'];
const typesWithPlatforms = ['Indicator'];
const typesWithTemporalRange = ['stix-core-relationship'];
const typesWithoutStatus = ['Stix-Core-Object', 'Stix-Domain-Object', 'Stix-Cyber-Observable', 'Artifact', 'ExternalReference'];

export interface UpdateFieldOption {
  label: string;
  value: string;
  disabled: boolean;
}

export interface UpdateFieldOptionsContext {
  steps: UpdateStep[];
  index: number;
  // The types of the selected elements and of the entity type filter
  selectedTypes: string[];
  entityTypeFilterValues: string[];
  // The types the list is about (its type and types props)
  contextTypes: string[];
  isAdmin: boolean;
  isUserDatatable: boolean;
  customFieldDefinitionsOfTypes: readonly { name: string; label: string; field_type: string }[];
  t: (text: string) => string;
}

// The fields a step can update, depending on its action type and on the targeted entity types
export const getUpdateFieldOptions = ({
  steps,
  index,
  selectedTypes,
  entityTypeFilterValues,
  contextTypes,
  isAdmin,
  isUserDatatable,
  customFieldDefinitionsOfTypes,
  t,
}: UpdateFieldOptionsContext): UpdateFieldOption[] => {
  const step = steps[index];
  const type = step?.type;
  const isAddReplaceOrRemove = type === 'ADD' || type === 'REPLACE' || type === 'REMOVE';
  const checkTypes = (typesList: string[]) => selectedTypes.every((entityType) => typesList.includes(entityType))
    && entityTypeFilterValues.every((entityType) => typesList.includes(entityType));
  const hasTemporalRangeField = entityTypeFilterValues.some((entityType) => typesWithTemporalRange.includes(entityType))
    || contextTypes.some((entityType) => typesWithTemporalRange.includes(entityType))
    || checkTypes(typesWithTemporalRange);

  let options: (false | { label: string; value: string })[] = [];
  if (isUserDatatable) {
    if (type === 'ADD' || type === 'REMOVE') {
      options = [
        { label: t('Organizations'), value: 'organizations' },
        { label: t('Groups'), value: 'groups' },
      ];
    }
    if (type === 'REPLACE') {
      options = [
        { label: t('Account status'), value: 'account_status' },
        { label: t('Account expiration date'), value: 'account_lock_after_date' },
        { label: t('Force password change date'), value: 'password_valid_until' },
      ];
    }
  } else {
    options = [
      { label: t('Marking definitions'), value: 'object-marking' },
      { label: t('Labels'), value: 'object-label' },
      checkTypes(typesWithAssignee) && { label: t('Assignees'), value: 'object-assignee' },
      checkTypes(typesWithParticipant) && { label: t('Participant'), value: 'object-participant' },
      (type === 'ADD' || type === 'REPLACE') && isAdmin && { label: t('Creator'), value: 'creator_id' },
      (type === 'ADD' || type === 'REMOVE') && { label: t('External references'), value: 'external-reference' },
      checkTypes(typesWithKillChains) && isAddReplaceOrRemove && { label: t('Kill chains'), value: 'killChainPhases' },
      checkTypes(typesWithIndicatorTypes) && isAddReplaceOrRemove && { label: t('Indicator types'), value: 'indicator_type_ov' },
      checkTypes(typesWithPlatforms) && isAddReplaceOrRemove && { label: t('Platforms'), value: 'platforms_ov' },
      hasTemporalRangeField && isAddReplaceOrRemove && { label: t('Start time'), value: 'start_time' },
      hasTemporalRangeField && isAddReplaceOrRemove && { label: t('Stop time'), value: 'stop_time' },
      ...(type === 'REPLACE' ? [
        { label: t('Author'), value: 'created-by' },
        { label: t('Confidence'), value: 'confidence' },
        { label: t('Description'), value: 'description' },
        checkTypes(typesWithSeverity) && { label: t('Severity'), value: 'case_severity_ov' },
        checkTypes(typesWithPriority) && { label: t('Priority'), value: 'case_priority_ov' },
        checkTypes(typesWithIncidentResponseType) && { label: t('Incident response type'), value: 'incident_response_types_ov' },
        checkTypes(typesWithRfiTypes) && { label: t('Request for information types'), value: 'request_for_information_types_ov' },
        checkTypes(typesWithRftTypes) && { label: t('Request for takedown types'), value: 'request_for_takedown_types_ov' },
        checkTypes(typesWithScore) && { label: t('Score'), value: 'x_opencti_score' },
        checkTypes(typesWithDetection) && { label: t('Detection'), value: 'x_opencti_detection' },
        selectedTypes.length === 1 && !typesWithoutStatus.includes(selectedTypes[0]) && { label: t('Status'), value: 'x_opencti_workflow_id' },
      ] : []),
      // As other attributes, a single value custom field is set by replace, a multi_select also accepts add
      ...customFieldDefinitionsOfTypes
        .filter((d) => type !== 'ADD' || d.field_type === 'multi_select')
        .map((d) => ({ label: d.label, value: d.name })),
    ];
  }

  // Disable some fields to prevent making several actions on the same key if one of them is a replace
  const selectedFields = steps.map((s) => s?.field).filter(Boolean);
  const replaceSelectedFields = steps.filter((s) => s?.type === 'REPLACE').map((s) => s.field).filter(Boolean);
  return options
    .filter((option): option is { label: string; value: string } => !!option)
    .sort((a, b) => a.label.localeCompare(b.label))
    .map((option) => ({
      ...option,
      disabled: (replaceSelectedFields.includes(option.value) && step?.field !== option.value)
        || (selectedFields.includes(option.value) && type === 'REPLACE'),
    }));
};
