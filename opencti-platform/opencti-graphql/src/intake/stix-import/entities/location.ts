import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, getAttributeInExtension, pickAliases } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate } from '../kwargs';

// pycti/entities/opencti_location.py (every location type through locationAdd)
const LOCATION_ADD = `
  mutation LocationAdd($input: LocationAddInput!) {
    locationAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// The aliases first; no granted refs for a location
const LOCATION_EXTENSION_FIELDS: [string, string][] = [
  ['x_opencti_aliases', 'aliases'],
  ['x_opencti_stix_ids', 'stix_ids'],
  ['x_opencti_workflow_id', 'workflow_id'],
  ['x_opencti_modified_at', 'modified_at'],
  ['opencti_upsert_operations', 'opencti_upsert_operations'],
];

// pycti opencti_location.py:create
const createLocation = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_location] Missing parameters: name');
    return null;
  }
  return mutate(context, LOCATION_ADD, 'locationAdd', {
    type: kw(kwargs, 'type'),
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
    latitude: kw(kwargs, 'latitude'),
    longitude: kw(kwargs, 'longitude'),
    precision: kw(kwargs, 'precision'),
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

// pycti opencti_location.py:import_from_stix2
export const importLocation = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  let name: unknown;
  if ('name' in object) {
    name = object.name;
  } else if ('city' in object) {
    name = object.city;
  } else if ('country' in object) {
    name = object.country;
  } else if ('region' in object) {
    name = object.region;
  } else {
    context.logger.error('[opencti_location] Missing name');
    return null;
  }
  // The location type: the OpenCTI one, else inferred from the STIX properties
  let type: unknown;
  if ('x_opencti_location_type' in object) {
    type = object.x_opencti_location_type;
  } else if (getAttributeInExtension('type', object) !== null) {
    type = getAttributeInExtension('type', object);
  } else if ('city' in object) {
    type = 'City';
  } else if ('country' in object) {
    type = 'Country';
  } else if ('region' in object) {
    type = 'Region';
  } else {
    type = 'Position';
  }
  // The aliases backfill always sets x_opencti_aliases, so pick_aliases never reaches the other keys
  backfillFromExtension(object, LOCATION_EXTENSION_FIELDS);
  return createLocation(context, {
    ...extrasArguments(extras),
    type,
    stix_id: object.id,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name,
    description: 'description' in object ? convertMarkdown(object.description) : null,
    latitude: field(object, 'latitude'),
    longitude: field(object, 'longitude'),
    precision: field(object, 'precision'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    x_opencti_aliases: pickAliases(object),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
