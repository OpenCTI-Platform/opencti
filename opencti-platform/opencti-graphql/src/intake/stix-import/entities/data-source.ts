import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_data_source.py (data-source and x-mitre-data-source)
const DATA_SOURCE_ADD = `
  mutation DataSourceAdd($input: DataSourceAddInput!) {
    dataSourceAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_data_source.py:create
const createDataSource = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_data_source] Missing parameters: name');
    return null;
  }
  return mutate(context, DATA_SOURCE_ADD, 'dataSourceAdd', {
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
    aliases: kw(kwargs, 'aliases'),
    // The platforms kwarg is sent as x_mitre_platforms
    x_mitre_platforms: kw(kwargs, 'platforms'),
    collection_layers: kw(kwargs, 'collection_layers'),
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

// pycti opencti_data_source.py:import_from_stix2
export const importDataSource = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  if (object.type === 'x-mitre-data-source' && 'x_mitre_collection_layers' in object) {
    object.collection_layers = object.x_mitre_collection_layers;
  }
  if (object.type === 'x-mitre-data-source' && 'x_mitre_platforms' in object) {
    object.platforms = object.x_mitre_platforms;
  }
  backfillFromExtension(object, STIX_DOMAIN_EXTENSION_FIELDS);
  return createDataSource(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    name: required(object, 'name'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    aliases: pickAliases(object),
    platforms: field(object, 'platforms'),
    collection_layers: field(object, 'collection_layers'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
