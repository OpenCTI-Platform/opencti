import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_opinion.py
const OPINION_ADD = `
  mutation OpinionAdd($input: OpinionAddInput!) {
    opinionAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_opinion.py:create (no upsert operations)
const createOpinion = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'opinion') === null) {
    context.logger.error('[opencti_opinion] Missing parameters: opinion');
    return null;
  }
  return mutate(context, OPINION_ADD, 'opinionAdd', {
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
    explanation: kw(kwargs, 'explanation'),
    authors: kw(kwargs, 'authors'),
    opinion: kw(kwargs, 'opinion'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    update: kw(kwargs, 'update', false),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
  });
};

// pycti opencti_opinion.py:import_from_stix2
export const importOpinion = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, [
    ['x_opencti_stix_ids', 'stix_ids'],
    ['x_opencti_granted_refs', 'granted_refs'],
    ['x_opencti_modified_at', 'modified_at'],
    ['x_opencti_workflow_id', 'workflow_id'],
  ]);
  return createOpinion(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    objects: field(extras, 'object_ids', []),
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    explanation: 'explanation' in object ? convertMarkdown(object.explanation) : null,
    authors: field(object, 'authors'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    opinion: field(object, 'opinion'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    update,
  });
};
