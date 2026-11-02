import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { convertMarkdown, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_incident.py (incident and x-opencti-incident)
const INCIDENT_ADD = `
  mutation IncidentAdd($input: IncidentAddInput!) {
    incidentAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_incident.py:create
const createIncident = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_incident] Missing parameters: name');
    return null;
  }
  return mutate(context, INCIDENT_ADD, 'incidentAdd', {
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
    first_seen: kw(kwargs, 'first_seen'),
    last_seen: kw(kwargs, 'last_seen'),
    incident_type: kw(kwargs, 'incident_type'),
    objective: kw(kwargs, 'objective'),
    severity: kw(kwargs, 'severity'),
    source: kw(kwargs, 'source'),
    x_opencti_score: kw(kwargs, 'x_opencti_score'),
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

// pycti opencti_incident.py:import_from_stix2
export const importIncident = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  backfillFromExtension(object, [...STIX_DOMAIN_EXTENSION_FIELDS, ['x_opencti_score', 'score']]);
  return createIncident(context, {
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
    incident_type: field(object, 'incident_type'),
    severity: field(object, 'severity'),
    source: field(object, 'source'),
    x_opencti_score: field(object, 'x_opencti_score'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
