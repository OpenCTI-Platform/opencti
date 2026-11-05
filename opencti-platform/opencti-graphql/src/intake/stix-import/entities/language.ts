import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_language.py
const LANGUAGE_ADD = `
  mutation LanguageAdd($input: LanguageAddInput!) {
    languageAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// No workflow nor upsert operations for a language (granted refs are read but never sent)
const LANGUAGE_EXTENSION_FIELDS: [string, string][] = [
  ['x_opencti_stix_ids', 'stix_ids'],
  ['x_opencti_granted_refs', 'granted_refs'],
  ['x_opencti_modified_at', 'modified_at'],
];

// pycti opencti_language.py:create
const createLanguage = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_language] Missing parameters: name');
    return null;
  }
  return mutate(context, LANGUAGE_ADD, 'languageAdd', {
    stix_id: kw(kwargs, 'stix_id'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    externalReferences: kw(kwargs, 'externalReferences'),
    revoked: kw(kwargs, 'revoked'),
    confidence: kw(kwargs, 'confidence'),
    lang: kw(kwargs, 'lang'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    name: kw(kwargs, 'name'),
    aliases: kw(kwargs, 'aliases'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    update: kw(kwargs, 'update', false),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
  });
};

// pycti opencti_language.py:import_from_stix2
export const importLanguage = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, LANGUAGE_EXTENSION_FIELDS);
  return createLanguage(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    aliases: pickAliases(object),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
  });
};
