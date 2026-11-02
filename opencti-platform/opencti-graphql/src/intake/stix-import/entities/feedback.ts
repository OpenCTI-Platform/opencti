import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_feedback.py
const FEEDBACK_ADD = `
  mutation FeedbackAdd($input: FeedbackAddInput!) {
    feedbackAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_feedback.py:create
const createFeedback = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_feedback] Missing parameters: name');
    return null;
  }
  return mutate(context, FEEDBACK_ADD, 'feedbackAdd', {
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
    description: kw(kwargs, 'description'),
    rating: kw(kwargs, 'rating'),
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

// pycti opencti_feedback.py:import_from_stix2
export const importFeedback = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, STIX_DOMAIN_EXTENSION_FIELDS);
  return createFeedback(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    objects: field(extras, 'object_ids', []),
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    rating: field(object, 'rating'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
