import type { ImportContext } from '../context';
import { nodesOf } from '../sub-objects';
import type { StixObject } from '../types';
import { convertMarkdown, getAttributeInExtension, getAttributeInMitreExtension, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs } from '../kwargs';

// pycti/entities/opencti_indicator.py
const INDICATOR_ADD = `
  mutation IndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) {
      id standard_id entity_type parent_types
      observables { edges { node { id standard_id entity_type } } }
    }
  }
`;

// pycti opencti_indicator.py:create
export const createIndicator = async (context: ImportContext, kwargs: Kwargs) => {
  const pattern = kw(kwargs, 'pattern');
  const name = kw(kwargs, 'name', pattern);
  const patternType = kw(kwargs, 'pattern_type');
  let mainObservableType = kw(kwargs, 'x_opencti_main_observable_type');
  if (name === null || pattern === null || patternType === null || mainObservableType === null) {
    context.logger.error('[opencti_indicator] Missing parameters: name or pattern or pattern_type or x_opencti_main_observable_type');
    return null;
  }
  if (mainObservableType === 'File') {
    mainObservableType = 'StixFile';
  }
  const data = await context.client.query(INDICATOR_ADD, {
    input: {
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
      pattern_type: patternType,
      pattern_version: kw(kwargs, 'pattern_version'),
      pattern,
      name,
      description: kw(kwargs, 'description'),
      indicator_types: kw(kwargs, 'indicator_types'),
      valid_until: kw(kwargs, 'valid_until'),
      valid_from: kw(kwargs, 'valid_from'),
      x_opencti_score: kw(kwargs, 'x_opencti_score', 50),
      x_opencti_detection: kw(kwargs, 'x_opencti_detection', false),
      x_opencti_main_observable_type: mainObservableType,
      x_mitre_platforms: kw(kwargs, 'x_mitre_platforms'),
      x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
      killChainPhases: kw(kwargs, 'killChainPhases'),
      createObservables: kw(kwargs, 'x_opencti_create_observables', false),
      x_opencti_workflow_id: kw(kwargs, 'x_opencti_workflow_id'),
      x_opencti_modified_at: kw(kwargs, 'x_opencti_modified_at'),
      update: kw(kwargs, 'update', false),
      files: kw(kwargs, 'files'),
      filesMarkings: kw(kwargs, 'filesMarkings'),
      noTriggerImport: kw(kwargs, 'noTriggerImport'),
      embedded: kw(kwargs, 'embedded'),
      upsertOperations: kw(kwargs, 'upsert_operations'),
    },
  });
  // pycti process_multiple_fields: the observables connection to a list (cached by import_object)
  const indicator = data.indicatorAdd;
  if (indicator && 'observables' in indicator) {
    indicator.observables = nodesOf(indicator.observables);
    indicator.observablesIds = indicator.observables.map((observable: any) => observable.id);
  }
  return indicator;
};

// pycti opencti_indicator.py:import_from_stix2
export const importIndicator = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  // Set even when the extension lacks them: the create defaults (score 50, detection false,
  // create observables false) then never apply and null is sent
  backfillFromExtension(object, [
    ['x_opencti_score', 'score'],
    ['x_opencti_detection', 'detection'],
  ]);
  if (!('x_opencti_main_observable_type' in object) && getAttributeInExtension('main_observable_type', object) !== null) {
    object.x_opencti_main_observable_type = getAttributeInExtension('main_observable_type', object);
  }
  backfillFromExtension(object, [
    ['x_opencti_create_observables', 'create_observables'],
    ['x_opencti_stix_ids', 'stix_ids'],
    ['x_opencti_granted_refs', 'granted_refs'],
    ['x_opencti_workflow_id', 'workflow_id'],
  ]);
  if (!('x_mitre_platforms' in object)) {
    object.x_mitre_platforms = getAttributeInMitreExtension('platforms', object);
  }
  backfillFromExtension(object, [
    ['x_opencti_modified_at', 'modified_at'],
    ['opencti_upsert_operations', 'opencti_upsert_operations'],
  ]);
  return createIndicator(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    pattern_type: field(object, 'pattern_type'),
    pattern_version: field(object, 'pattern_version'),
    pattern: field(object, 'pattern', ''),
    name: 'name' in object ? object.name : required(object, 'pattern'),
    description: 'description' in object ? convertMarkdown(object.description) : null,
    indicator_types: field(object, 'indicator_types'),
    valid_from: field(object, 'valid_from'),
    valid_until: field(object, 'valid_until'),
    x_opencti_score: field(object, 'x_opencti_score', 50),
    x_opencti_detection: field(object, 'x_opencti_detection', false),
    x_mitre_platforms: field(object, 'x_mitre_platforms'),
    x_opencti_main_observable_type: field(object, 'x_opencti_main_observable_type', 'Unknown'),
    killChainPhases: field(extras, 'kill_chain_phases_ids'),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    x_opencti_create_observables: field(object, 'x_opencti_create_observables', false),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
