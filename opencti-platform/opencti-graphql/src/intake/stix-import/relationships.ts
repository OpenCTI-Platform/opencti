import { type ImportContext, setInCache } from './context';
import { guessPastDate } from './dates';
import { embeddedExtras, extractEmbeddedRelationships } from './embedded';
import { addObjectToReport } from './entities/report';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from './kwargs';
import type { StixObject } from './types';
import { contains, convertMarkdown, dictGet, extractCustomFieldValues, getAttributeInExtension, iterate, required } from './utils';

// pycti import_relationship and import_sighting (pycti/utils/opencti_stix2.py), with the creates
// of pycti/entities/opencti_stix_core_relationship.py and opencti_stix_sighting_relationship.py

const STIX_CORE_RELATIONSHIP_ADD = `
  mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

const STIX_SIGHTING_RELATIONSHIP_ADD = `
  mutation StixSightingRelationshipAdd($input: StixSightingRelationshipAddInput!) {
    stixSightingRelationshipAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_stix_core_relationship.py:create (no required field check)
export const createStixCoreRelationship = async (context: ImportContext, kwargs: Kwargs) => {
  return mutate(context, STIX_CORE_RELATIONSHIP_ADD, 'stixCoreRelationshipAdd', {
    fromId: kw(kwargs, 'fromId'),
    toId: kw(kwargs, 'toId'),
    stix_id: kw(kwargs, 'stix_id'),
    relationship_type: kw(kwargs, 'relationship_type'),
    description: kw(kwargs, 'description'),
    start_time: kw(kwargs, 'start_time'),
    stop_time: kw(kwargs, 'stop_time'),
    revoked: kw(kwargs, 'revoked'),
    confidence: kw(kwargs, 'confidence'),
    lang: kw(kwargs, 'lang'),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    objectOrganization: kw(kwargs, 'objectOrganization'),
    externalReferences: kw(kwargs, 'externalReferences'),
    killChainPhases: kw(kwargs, 'killChainPhases'),
    x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    external_uri: kw(kwargs, 'external_uri'),
    coverage_information: kw(kwargs, 'coverage_information'),
    update: kw(kwargs, 'update', false),
    upsertOperations: kw(kwargs, 'upsert_operations'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
  });
};

// pycti opencti_stix_core_relationship.py:import_from_stix2 (defaultDate: the date guessed from
// the external references, used when start_time or stop_time is absent)
const importStixCoreRelationship = async (context: ImportContext, relation: StixObject, extras: Kwargs, update: boolean, defaultDate: string | null) => {
  backfillFromExtension(relation, STIX_DOMAIN_EXTENSION_FIELDS);
  const rawCoverages = field(relation, 'coverage', []);
  const coverageInformation = iterate(rawCoverages)
    .filter((coverage) => contains(coverage, 'score'))
    .map((coverage) => ({ coverage_name: required(coverage, 'name'), coverage_score: required(coverage, 'score') }));
  const { createdBy, objectMarking, objectLabel, externalReferences, custom_field_values } = extrasArguments(extras);
  return createStixCoreRelationship(context, {
    fromId: required(relation, 'source_ref'),
    toId: required(relation, 'target_ref'),
    stix_id: relation.id,
    relationship_type: required(relation, 'relationship_type'),
    description: 'description' in relation ? convertMarkdown(relation.description) : null,
    start_time: field(relation, 'start_time', defaultDate),
    stop_time: field(relation, 'stop_time', defaultDate),
    external_uri: field(relation, 'external_uri'),
    coverage_information: coverageInformation,
    revoked: field(relation, 'revoked'),
    confidence: field(relation, 'confidence'),
    lang: field(relation, 'lang'),
    created: field(relation, 'created'),
    modified: field(relation, 'modified'),
    createdBy,
    objectMarking,
    objectLabel,
    externalReferences,
    killChainPhases: field(extras, 'kill_chain_phases_ids'),
    objectOrganization: field(relation, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(relation, 'x_opencti_workflow_id'),
    x_opencti_stix_ids: field(relation, 'x_opencti_stix_ids'),
    x_opencti_modified_at: field(relation, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(relation, 'opencti_upsert_operations'),
    custom_field_values,
  });
};

// pycti opencti_stix_sighting_relationship.py:create (no required field check)
const createStixSightingRelationship = async (context: ImportContext, kwargs: Kwargs) => {
  return mutate(context, STIX_SIGHTING_RELATIONSHIP_ADD, 'stixSightingRelationshipAdd', {
    fromId: kw(kwargs, 'fromId'),
    toId: kw(kwargs, 'toId'),
    stix_id: kw(kwargs, 'stix_id'),
    description: kw(kwargs, 'description'),
    first_seen: kw(kwargs, 'first_seen'),
    last_seen: kw(kwargs, 'last_seen'),
    attribute_count: kw(kwargs, 'count'),
    x_opencti_negative: kw(kwargs, 'x_opencti_negative', false),
    created: kw(kwargs, 'created'),
    modified: kw(kwargs, 'modified'),
    confidence: kw(kwargs, 'confidence'),
    createdBy: kw(kwargs, 'createdBy'),
    objectMarking: kw(kwargs, 'objectMarking'),
    objectLabel: kw(kwargs, 'objectLabel'),
    externalReferences: kw(kwargs, 'externalReferences'),
    x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
    x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
    x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
    objectOrganization: kw(kwargs, 'objectOrganization'),
    update: kw(kwargs, 'update', false),
    upsertOperations: kw(kwargs, 'upsert_operations'),
    customFieldValues: kw(kwargs, 'custom_field_values'),
  });
};

// pycti opencti_stix2.py:import_relationship
export const importRelationship = async (context: ImportContext, item: StixObject, update: boolean, types: string[] | null) => {
  const extras: Kwargs = {
    ...embeddedExtras(await extractEmbeddedRelationships(context, item, types)),
    // Read before import_from_stix2 copies the extension fields to the top level
    custom_field_values: extractCustomFieldValues(item),
  };
  // Start and stop times guessed from the external references: the last reference wins, even
  // when nothing is found in it. Each reference is read (same failures as pycti), only the last
  // text is searched (guess_past_date never fails, the earlier results are overwritten).
  let date: string | null = null;
  if ('external_references' in item) {
    const references = iterate(item.external_references);
    let text: unknown = null;
    references.forEach((reference) => {
      text = contains(reference, 'description') ? required(reference, 'description') : dictGet(reference, 'source_name');
    });
    if (references.length > 0) {
      date = guessPastDate(text, context.now);
    }
  }
  const result = await importStixCoreRelationship(context, item, extras, update, date);
  if (result === null || result === undefined) {
    return null;
  }
  setInCache(context, item.id, { id: required(result, 'id'), type: required(result, 'entity_type') });
  // Reports built from the external references (types external-reference-as-report)
  for (const referenceId of extras.external_references_ids) {
    if (contains(extras.reports, referenceId)) {
      const reportId = required(extras.reports[referenceId], 'id');
      await addObjectToReport(context, reportId, result.id);
      await addObjectToReport(context, reportId, item.source_ref);
      await addObjectToReport(context, reportId, item.target_ref);
    }
  }
  return result;
};

// pycti opencti_stix2.py:import_sighting (pycti passes no types: no report from the references)
export const importSighting = async (context: ImportContext, item: StixObject, fromId: unknown, toId: unknown, update: boolean) => {
  const extras = embeddedExtras(await extractEmbeddedRelationships(context, item, null));
  const upsertOperations = getAttributeInExtension('opencti_upsert_operations', item);
  // The sighting itself is completed, before its custom fields are read
  if (!('x_opencti_negative' in item) && getAttributeInExtension('negative', item) !== null) {
    item.x_opencti_negative = getAttributeInExtension('negative', item);
  }
  if (!('x_opencti_workflow_id' in item)) {
    item.x_opencti_workflow_id = getAttributeInExtension('workflow_id', item);
  }
  const result = await createStixSightingRelationship(context, {
    fromId,
    toId,
    stix_id: field(item, 'id'),
    description: 'description' in item ? convertMarkdown(item.description) : null,
    first_seen: field(item, 'first_seen'),
    last_seen: field(item, 'last_seen'),
    count: field(item, 'count', 1),
    x_opencti_negative: field(item, 'x_opencti_negative', false),
    created: field(item, 'created'),
    modified: field(item, 'modified'),
    confidence: field(item, 'confidence'),
    createdBy: extras.created_by_id,
    objectMarking: extras.object_marking_ids,
    objectLabel: extras.object_label_ids,
    externalReferences: extras.external_references_ids,
    objectOrganization: extras.granted_refs_ids,
    x_opencti_workflow_id: field(item, 'x_opencti_workflow_id'),
    x_opencti_stix_ids: field(item, 'x_opencti_stix_ids'),
    update,
    upsert_operations: upsertOperations,
    custom_field_values: extractCustomFieldValues(item),
  });
  if (result === null || result === undefined) {
    return null;
  }
  setInCache(context, item.id, { id: result.id, type: result.entity_type });
  return result;
};
