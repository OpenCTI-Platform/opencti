import type { ImportContext } from '../context';
import type { StixObject } from '../types';
import { asStr, contains, convertMarkdown, getAttributeInExtension, getAttributeInMitreExtension, iterate, pickAliases, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_attack_pattern.py
const ATTACK_PATTERN_ADD = `
  mutation AttackPatternAdd($input: AttackPatternAddInput!) {
    attackPatternAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_attack_pattern.py:create
const createAttackPattern = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null) {
    context.logger.error('[opencti_attack_pattern] Missing parameters: name');
    return null;
  }
  return mutate(context, ATTACK_PATTERN_ADD, 'attackPatternAdd', {
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
    x_mitre_platforms: kw(kwargs, 'x_mitre_platforms'),
    x_mitre_permissions_required: kw(kwargs, 'x_mitre_permissions_required'),
    x_mitre_detection: kw(kwargs, 'x_mitre_detection'),
    x_mitre_id: kw(kwargs, 'x_mitre_id'),
    killChainPhases: kw(kwargs, 'killChainPhases'),
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

// pycti opencti_attack_pattern.py:import_from_stix2
export const importAttackPattern = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  let xMitreId: unknown = null;
  if ('x_mitre_id' in object) {
    xMitreId = object.x_mitre_id;
  } else if (getAttributeInMitreExtension('id', object) !== null) {
    xMitreId = getAttributeInMitreExtension('id', object);
  } else if ('external_references' in object) {
    // No break: the last MITRE reference wins
    iterate(object.external_references).forEach((externalReference) => {
      if (asStr(required(externalReference, 'source_name'), 'startswith').startsWith('mitre-')) {
        xMitreId = contains(externalReference, 'external_id') ? required(externalReference, 'external_id') : null;
      }
    });
  }
  if (!('x_opencti_order' in object)) {
    const order = getAttributeInExtension('order', object);
    object.x_opencti_order = order !== null ? order : 0;
  }
  // These backfills always set the key, so the x_amitt_platforms fallback below is never reached
  if (!('x_mitre_platforms' in object)) {
    object.x_mitre_platforms = getAttributeInMitreExtension('platforms', object);
  }
  if (!('x_mitre_permissions_required' in object)) {
    object.x_mitre_permissions_required = getAttributeInMitreExtension('permissions_required', object);
  }
  if (!('x_mitre_detection' in object)) {
    object.x_mitre_detection = getAttributeInMitreExtension('detection', object);
  }
  backfillFromExtension(object, STIX_DOMAIN_EXTENSION_FIELDS);
  return createAttackPattern(context, {
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
    x_mitre_platforms: 'x_mitre_platforms' in object ? object.x_mitre_platforms : field(object, 'x_amitt_platforms'),
    x_mitre_permissions_required: field(object, 'x_mitre_permissions_required'),
    x_mitre_detection: field(object, 'x_mitre_detection'),
    x_mitre_id: xMitreId,
    killChainPhases: field(extras, 'kill_chain_phases_ids'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
