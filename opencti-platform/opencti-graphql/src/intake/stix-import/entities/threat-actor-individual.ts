import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_threat_actor_individual.py
const THREAT_ACTOR_INDIVIDUAL_ADD = `
  mutation ThreatActorIndividualAdd($input: ThreatActorIndividualAddInput!) {
    threatActorIndividualAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_threat_actor_individual.py:create (no score, unlike the group)
const createThreatActorIndividual = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_threat_actor_individual] Missing parameters: name');
    return null;
  }
  return mutate(context, THREAT_ACTOR_INDIVIDUAL_ADD, 'threatActorIndividualAdd', {
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
    threat_actor_types: kw(kwargs, 'threat_actor_types'),
    first_seen: kw(kwargs, 'first_seen'),
    last_seen: kw(kwargs, 'last_seen'),
    roles: kw(kwargs, 'roles'),
    goals: kw(kwargs, 'goals'),
    sophistication: kw(kwargs, 'sophistication'),
    resource_level: kw(kwargs, 'resource_level'),
    primary_motivation: kw(kwargs, 'primary_motivation'),
    secondary_motivations: kw(kwargs, 'secondary_motivations'),
    personal_motivations: kw(kwargs, 'personal_motivations'),
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

// pycti opencti_threat_actor_individual.py:import_from_stix2
export const importThreatActorIndividual = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, STIX_DOMAIN_EXTENSION_FIELDS);
  return createThreatActorIndividual(context, {
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
    threat_actor_types: field(object, 'threat_actor_types'),
    first_seen: field(object, 'first_seen'),
    last_seen: field(object, 'last_seen'),
    roles: field(object, 'roles'),
    goals: field(object, 'goals'),
    sophistication: field(object, 'sophistication'),
    resource_level: field(object, 'resource_level'),
    primary_motivation: field(object, 'primary_motivation'),
    secondary_motivations: field(object, 'secondary_motivations'),
    personal_motivations: field(object, 'personal_motivations'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
