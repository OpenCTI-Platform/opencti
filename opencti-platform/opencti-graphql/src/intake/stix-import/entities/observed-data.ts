import type { ImportContext } from '../context';
import { createStixCyberObservable } from '../observables-create';
import type { StixObject } from '../types';
import { dictItems, getAttributeInExtension, required } from '../utils';
import { backfillFromExtension, extrasArguments, field, kw, type Kwargs, mutate, STIX_DOMAIN_EXTENSION_FIELDS } from '../kwargs';

// pycti/entities/opencti_observed_data.py
const OBSERVED_DATA_ADD = `
  mutation ObservedDataAdd($input: ObservedDataAddInput!) {
    observedDataAdd(input: $input) { id standard_id entity_type parent_types }
  }
`;

// pycti opencti_observed_data.py:create
const createObservedData = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'first_observed') === null || kw(kwargs, 'last_observed') === null || kw(kwargs, 'objects') === null) {
    context.logger.error('[opencti_observed_data] Missing parameters: first_observed, last_observed or objects');
    return null;
  }
  return mutate(context, OBSERVED_DATA_ADD, 'observedDataAdd', {
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
    first_observed: kw(kwargs, 'first_observed'),
    last_observed: kw(kwargs, 'last_observed'),
    number_observed: kw(kwargs, 'number_observed'),
    number_seen: kw(kwargs, 'number_seen'),
    max_distinct_count: kw(kwargs, 'max_distinct_count'),
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

// pycti opencti_observed_data.py:import_from_stix2
export const importObservedData = async (context: ImportContext, object: StixObject, extras: Kwargs, update: boolean) => {
  // The same list as extras object_ids (and as the object's object_refs), appended in place
  const objectRefs: unknown[] = field(extras, 'object_ids', []);
  // STIX 2.0: the observables embedded in `objects` are created first
  if ('objects' in object) {
    const observableResults: any[] = [];
    for (const [, observableItem] of dictItems(object.objects)) {
      observableResults.push(await createStixCyberObservable(context, {
        observableData: observableItem,
        createdBy: field(extras, 'created_by_id'),
        objectMarking: field(extras, 'object_marking_ids'),
        objectLabel: field(extras, 'object_label_ids'),
        objectOrganization: field(extras, 'granted_refs_ids'),
      }));
      // pycti appends every result so far at each turn: [o1, o1, o2, ...]
      for (const item of observableResults) {
        objectRefs.push(required(item, 'standard_id'));
      }
    }
  }
  backfillFromExtension(object, STIX_DOMAIN_EXTENSION_FIELDS);
  return createObservedData(context, {
    ...extrasArguments(extras),
    stix_id: object.id,
    objects: objectRefs,
    revoked: field(object, 'revoked'),
    confidence: field(object, 'confidence'),
    lang: field(object, 'lang'),
    created: field(object, 'created'),
    modified: field(object, 'modified'),
    first_observed: field(object, 'first_observed'),
    last_observed: field(object, 'last_observed'),
    number_observed: field(object, 'number_observed'),
    number_seen: getAttributeInExtension('number_seen', object),
    max_distinct_count: getAttributeInExtension('max_distinct_count', object),
    x_opencti_stix_ids: field(object, 'x_opencti_stix_ids'),
    objectOrganization: field(object, 'x_opencti_granted_refs'),
    x_opencti_workflow_id: field(object, 'x_opencti_workflow_id'),
    x_opencti_modified_at: field(object, 'x_opencti_modified_at'),
    update,
    upsert_operations: field(object, 'opencti_upsert_operations'),
  });
};
