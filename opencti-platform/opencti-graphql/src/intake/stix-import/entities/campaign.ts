import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_campaign.py
const CAMPAIGN_ADD = `
  mutation CampaignAdd($input: CampaignAddInput!) {
    campaignAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_campaign.py:create
const createCampaign = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_campaign] Missing parameters: name');
    return null;
  }
  return mutate(context, CAMPAIGN_ADD, 'campaignAdd', {
    stix_id: kw(kwargs, 'stix_id'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectOrganization: kw(kwargs, 'objectOrganization'),
    objectLabel: kw(kwargs, 'objectLabel'),
    externalReferences: kw(kwargs, 'externalReferences'),
    revoked: kw(kwargs, 'revoked'),
    confidence: kw(kwargs, 'confidence'),
    lang: kw(kwargs, 'lang'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    name: kw(kwargs, 'name'),
    description: kw(kwargs, 'description'),
    aliases: kw(kwargs, 'aliases'),
    first_seen: kw(kwargs, 'first_seen'),
    last_seen: kw(kwargs, 'last_seen'),
    objective: kw(kwargs, 'objective'),
    update: kw(kwargs, 'update', false),
    x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    files: kw(kwargs, 'files'),
    filesMarkings: kw(kwargs, 'filesMarkings'),
    noTriggerImport: kw(kwargs, 'noTriggerImport'),
    embedded: kw(kwargs, 'embedded'),
    upsertOperations: kw(kwargs, 'upsert_operations'),
  });
};

// pycti opencti_campaign.py:import_from_stix2
export const importCampaign = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, STIX_DOMAIN_EXTENSION_FIELDS);
  return createCampaign(context, {
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
    objective: field(object, 'objective'),
    first_seen: field(object, 'first_seen'),
    last_seen: field(object, 'last_seen'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
