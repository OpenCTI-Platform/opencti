import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, dictGet, getAttributeInMitreExtension, iterate, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_course_of_action.py
const COURSE_OF_ACTION_ADD = `
  mutation CourseOfActionAdd($input: CourseOfActionAddInput!) {
    courseOfActionAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

const MITRE_SOURCES = ['mitre-attack', 'mitre-pre-attack', 'mitre-mobile-attack', 'amitt-attack'];

// pycti opencti_course_of_action.py:create
const createCourseOfAction = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_course_of_action] Missing parameters: name');
    return null;
  }
  return mutate(context, COURSE_OF_ACTION_ADD, 'courseOfActionAdd', {
    stix_id: kw(kwargs, 'stix_id'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    objectOrganization: kw(kwargs, 'objectOrganization'),
    externalReferences: kw(kwargs, 'externalReferences'),
    revoked: kw(kwargs, 'revoked'),
    confidence: kw(kwargs, 'confidence'),
    lang: kw(kwargs, 'lang'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    name: kw(kwargs, 'name'),
    description: kw(kwargs, 'description'),
    x_opencti_aliases: kw(kwargs, 'x_opencti_aliases'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_mitre_id: kw(kwargs, 'x_mitre_id'),
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

// pycti opencti_course_of_action.py:import_from_stix2
export const importCourseOfAction = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  let xMitreId: unknown = null;
  if ('x_mitre_id' in object) {
    xMitreId = object.x_mitre_id;
  } else if (getAttributeInMitreExtension('id', object) !== null) {
    xMitreId = getAttributeInMitreExtension('id', object);
  } else if ('external_references' in object) {
    // No break: the last MITRE reference wins
    iterate(object.external_references).forEach((externalReference) => {
      if (MITRE_SOURCES.includes(required(externalReference, 'source_name'))) {
        xMitreId = dictGet(externalReference, 'external_id');
      }
    });
  }
  // The aliases backfill always sets x_opencti_aliases, so pick_aliases never reaches the other keys
  backfillFromExtension(object, [['x_opencti_aliases', 'aliases'], ...STIX_DOMAIN_EXTENSION_FIELDS]);
  return createCourseOfAction(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    x_opencti_aliases: pickAliases(object),
    x_mitre_id: xMitreId,
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
