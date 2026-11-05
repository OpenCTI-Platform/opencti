import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, getAttributeInExtension, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_event.py
const EVENT_ADD = `
  mutation EventAdd($input: EventAddInput!) {
    eventAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// No workflow for an event (granted refs are read but never sent)
const EVENT_EXTENSION_FIELDS: [string, string][] = [
  ['x_opencti_stix_ids', 'stix_ids'],
  ['x_opencti_granted_refs', 'granted_refs'],
  ['x_opencti_modified_at', 'modified_at'],
  ['opencti_upsert_operations', 'opencti_upsert_operations'],
];

// pycti opencti_event.py:create
const createEvent = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_event] Missing parameters: name');
    return null;
  }
  return mutate(context, EVENT_ADD, 'eventAdd', {
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
    description: kw(kwargs, 'description'),
    x_opencti_score: kw(kwargs, 'x_opencti_score'),
    aliases: kw(kwargs, 'aliases'),
    start_time: kw(kwargs, 'start_time'),
    stop_time: kw(kwargs, 'stop_time'),
    event_types: kw(kwargs, 'event_types'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    update: kw(kwargs, 'update', false),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
    upsertOperations: kw(kwargs, 'upsert_operations'),
  });
};

// pycti opencti_event.py:import_from_stix2
export const importEvent = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, EVENT_EXTENSION_FIELDS);
  return createEvent(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    x_opencti_score: 'x_opencti_score' in object ? object.x_opencti_score : getAttributeInExtension('score', object),
    aliases: pickAliases(object),
    event_types: field(object, 'event_types'),
    start_time: field(object, 'start_time'),
    stop_time: field(object, 'stop_time'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
