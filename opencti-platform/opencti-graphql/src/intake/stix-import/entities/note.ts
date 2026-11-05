import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_note.py
const NOTE_ADD = `
  mutation NoteAdd($input: NoteAddInput!) {
    noteAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_note.py:create
const createNote = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'content') === null) {
    context.logger.error('[opencti_note] Missing parameters: content');
    return null;
  }
  return mutate(context, NOTE_ADD, 'noteAdd', {
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
    attribute_abstract: kw(kwargs, 'abstract'),
    content: kw(kwargs, 'content'),
    authors: kw(kwargs, 'authors'),
    note_types: kw(kwargs, 'note_types'),
    likelihood: kw(kwargs, 'likelihood'),
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

// pycti opencti_note.py:import_from_stix2
export const importNote = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, [
    ['x_opencti_stix_ids', 'stix_ids'],
    ['x_opencti_granted_refs', 'granted_refs'],
    ['x_opencti_workflow_id', 'workflow_id'],
    ['x_opencti_modified_at', 'modified_at'],
    ['opencti_upsert_operations', 'opencti_upsert_operations'],
  ]);
  return createNote(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    objects: field(extras, 'object_ids', []),
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    abstract: 'abstract' in object ? convertMarkdown(object.abstract) : null,
    content: 'content' in object ? convertMarkdown(object.content) : null,
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    authors: field(object, 'authors'),
    note_types: field(object, 'note_types'),
    likelihood: field(object, 'likelihood'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
