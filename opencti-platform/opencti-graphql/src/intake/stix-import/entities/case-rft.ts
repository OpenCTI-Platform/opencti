import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, getAttributeInExtension, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_case_rft.py
const CASE_RFT_ADD = `
  mutation CaseRftAdd($input: CaseRftAddInput!) {
    caseRftAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_case_rft.py:create
const createCaseRft = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_case_rft] Missing parameters: name');
    return null;
  }
  return mutate(context, CASE_RFT_ADD, 'caseRftAdd', {
    stix_id: kw(kwargs, 'stix_id'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    objectOrganization: kw(kwargs, 'objectOrganization'),
    objectAssignee: kw(kwargs, 'objectAssignee'),
    objectParticipant: kw(kwargs, 'objectParticipant'),
    objects: kw(kwargs, 'objects'),
    externalReferences: kw(kwargs, 'externalReferences'),
    revoked: kw(kwargs, 'revoked'),
    severity: kw(kwargs, 'severity'),
    priority: kw(kwargs, 'priority'),
    confidence: kw(kwargs, 'confidence'),
    lang: kw(kwargs, 'lang'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    name: kw(kwargs, 'name'),
    description: kw(kwargs, 'description'),
    content: kw(kwargs, 'content'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    update: kw(kwargs, 'update', false),
    takedown_types: kw(kwargs, 'takedown_types'),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
    upsertOperations: kw(kwargs, 'upsert_operations'),
  });
};

// pycti opencti_case_rft.py:import_from_stix2
export const importCaseRft = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, [
    ['x_opencti_stix_ids', 'stix_ids'],
    ['x_opencti_granted_refs', 'granted_refs'],
  ]);
  if (!('x_opencti_content' in object) || !('content' in object)) {
    object.content = getAttributeInExtension('content', object);
  }
  if ('x_opencti_content' in object) {
    object.content = object.x_opencti_content;
  }
  backfillFromExtension(object, [
    ['x_opencti_workflow_id', 'workflow_id'],
    ['x_opencti_assignee_ids', 'assignee_ids'],
    ['x_opencti_participant_ids', 'participant_ids'],
    ['x_opencti_modified_at', 'modified_at'],
    ['opencti_upsert_operations', 'opencti_upsert_operations'],
  ]);
  return createCaseRft(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    objects: field(extras, 'object_ids', []),
    content: 'content' in object ? convertMarkdown(object.content) : null,
    revoked: field(object, 'revoked'),
    severity: field(object, 'severity'),
    priority: field(object, 'priority'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    objectAssignee: field(object, 'x_opencti_assignee_ids'),
    objectParticipant: field(object, 'x_opencti_participant_ids'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    takedown_types: field(object, 'takedown_types'),
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
