import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, getAttributeInExtension, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_report.py
const REPORT_ADD = `
  mutation ReportAdd($input: ReportAddInput!) {
    reportAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;
const REPORT_RELATION_ADD = `
  mutation ReportEditRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
    reportEdit(id: $id) { relationAdd(input: $input) { id } }
  }
`;

// pycti opencti_report.py:create
export const createReport = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null || kw(kwargs, 'published') === null) {
    context.logger.error('[opencti_report] Missing parameters: name and published');
    return null;
  }
  return mutate(context, REPORT_ADD, 'reportAdd', {
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
    confidence: kw(kwargs, 'confidence'),
    lang: kw(kwargs, 'lang'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    name: kw(kwargs, 'name'),
    description: kw(kwargs, 'description'),
    content: kw(kwargs, 'content'),
    report_types: kw(kwargs, 'report_types'),
    published: kw(kwargs, 'published'),
    x_opencti_reliability: kw(kwargs, 'x_opencti_reliability'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    update: kw(kwargs, 'update', false),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
    upsertOperations: kw(kwargs, 'upsert_operations'),
  });
};

// pycti report.add_stix_object_or_stix_relationship
export const addObjectToReport = async (context: ImportContext, reportId: string, objectId: string) => {
  await context.client.query(REPORT_RELATION_ADD, { id: reportId, input: { toId: objectId, relationship_type: 'object' } });
  return true;
};

// pycti opencti_report.py:import_from_stix2
export const importReport = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, [
    ['x_opencti_stix_ids', 'stix_ids'],
    ['x_opencti_granted_refs', 'granted_refs'],
    ['x_opencti_workflow_id', 'workflow_id'],
    ['x_opencti_reliability', 'reliability'],
  ]);
  if (!('x_opencti_content' in object) || !('content' in object)) {
    object.content = getAttributeInExtension('content', object);
  }
  if ('x_opencti_content' in object) {
    object.content = object.x_opencti_content;
  }
  backfillFromExtension(object, [
    ['x_opencti_assignee_ids', 'assignee_ids'],
    ['x_opencti_participant_ids', 'participant_ids'],
    ['x_opencti_modified_at', 'modified_at'],
    ['opencti_upsert_operations', 'opencti_upsert_operations'],
  ]);
  return createReport(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    objectAssignee: field(object, 'x_opencti_assignee_ids'),
    objectParticipant: field(object, 'x_opencti_participant_ids'),
    objects: field(extras, 'object_ids', []),
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    content: 'content' in object ? convertMarkdown(object.content) : null,
    report_types: field(object, 'report_types'),
    published: field(object, 'published'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    x_opencti_reliability: field(object, 'x_opencti_reliability'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
