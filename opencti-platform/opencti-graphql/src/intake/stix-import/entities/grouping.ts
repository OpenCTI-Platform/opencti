import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, getAttributeInExtension, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_grouping.py
const GROUPING_ADD = `
  mutation GroupingAdd($input: GroupingAddInput!) {
    groupingAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_grouping.py:create
const createGrouping = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null || kw(kwargs, 'context') === null) {
    context.logger.error('[opencti_grouping] Missing parameters: name and context');
    return null;
  }
  return mutate(context, GROUPING_ADD, 'groupingAdd', {
    stix_id: kw(kwargs, 'stix_id'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    objectOrganization: kw(kwargs, 'objectOrganization'),
    objects: kw(kwargs, 'objects'),
    externalReferences: kw(kwargs, 'externalReferences'),
    revoked: kw(kwargs, 'revoked'),
    confidence: kw(kwargs, 'confidence'),
    lang: kw(kwargs, 'lang'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    name: kw(kwargs, 'name'),
    context: kw(kwargs, 'context'),
    content: kw(kwargs, 'content'),
    description: kw(kwargs, 'description'),
    x_opencti_aliases: kw(kwargs, 'x_opencti_aliases'),
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

// pycti opencti_grouping.py:import_from_stix2
export const importGrouping = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, [
    ['x_opencti_aliases', 'aliases'],
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
    ['x_opencti_modified_at', 'modified_at'],
    ['opencti_upsert_operations', 'opencti_upsert_operations'],
  ]);
  return createGrouping(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    objects: field(extras, 'object_ids', []),
    content: 'content' in object ? convertMarkdown(object.content) : null,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    context: required(object, 'context'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_aliases: pickAliases(object),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
