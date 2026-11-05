import { field } from './kwargs';
import { type ImportContext, setInCache } from './context';
import { embeddedExtras, extractEmbeddedRelationships } from './embedded';
import { fileObjectsOf, filesInput, createExternalReference, createKillChainPhase, createLabel, createVocabulary } from './sub-objects';
import { STIX_IMPORTERS } from './entities/registry';
import { addObjectToReport } from './entities/report';
import { importObservable } from './observables';
import { importRelationship, importSighting } from './relationships';
import { applyOpenctiOperation } from './operations';
import type { StixObject } from './types';
import { asStr, contains, extractCustomFieldValues, getAttributeInExtension, isStixCyberObservableType, iterate, pythonTruthy, required, tableGet } from './utils';

// pycti OpenCTIStix2.import_item and import_object: one STIX object (of a split bundle) to its
// GraphQL operations

const importObject = async (context: ImportContext, object: StixObject, update: boolean, types: string[] | null) => {
  const embedded = await extractEmbeddedRelationships(context, object, types);
  const fileObjects = fileObjectsOf(object);
  const extras = {
    ...embeddedExtras(embedded),
    ...filesInput(fileObjects),
    custom_field_values: extractCustomFieldValues(object),
  };
  // pycti get_stix_helper().get(type): a dict lookup, never through the registry's prototype
  const importer = tableGet(STIX_IMPORTERS, required(object, 'type'));
  let results: any = null;
  if (importer) {
    results = await importer(context, object, extras, update);
  } else {
    context.logger.error('Unknown object type, doing nothing...', { type: object.type });
  }
  if (results === null || results === undefined) {
    return null;
  }
  const resultList = Array.isArray(results) ? results : [results];
  for (const result of resultList) {
    const cached = { id: required(result, 'id'), type: required(result, 'entity_type'), observables: result.observables ?? [] };
    setInCache(context, object.id, cached);
    setInCache(context, result.id, cached);
    for (const referenceId of embedded.external_references) {
      if (contains(embedded.reports, referenceId)) {
        await addObjectToReport(context, required(embedded.reports[referenceId], 'id'), result.id);
      }
    }
  }
  return resultList;
};

const importSightings = async (context: ImportContext, item: StixObject, update: boolean) => {
  let toIds: string[] = [];
  if ('x_opencti_where_sighted_refs' in item) {
    toIds = [...iterate(item.x_opencti_where_sighted_refs) as string[]];
  } else if ('where_sighted_refs' in item) {
    toIds = [...iterate(item.where_sighted_refs) as string[]];
  }
  let fromId: unknown = null;
  if ('x_opencti_sighting_of_ref' in item) {
    fromId = item.x_opencti_sighting_of_ref;
  } else if ('sighting_of_ref' in item) {
    fromId = item.sighting_of_ref;
  }
  if (toIds.length > 0) {
    if (pythonTruthy(fromId)) {
      for (const toId of toIds) {
        await importSighting(context, item, fromId, toId, update);
      }
    }
    if ('observed_data_refs' in item) {
      for (const observedDataRef of iterate(item.observed_data_refs) as string[]) {
        for (const toId of toIds) {
          await importSighting(context, item, observedDataRef, toId, update);
        }
      }
    }
  }
};

const isInScope = (item: StixObject, types: string[]) => {
  if (item.type === 'identity') {
    if ('identity_class' in item) {
      return ((types.includes('class') || types.includes('sector')) && item.identity_class === 'class') || types.includes(item.identity_class);
    }
    return false;
  }
  if (item.type === 'location') {
    if ('x_opencti_location_type' in item) {
      return types.includes(asStr(item.x_opencti_location_type, 'lower').toLowerCase());
    }
    const locationType = getAttributeInExtension('location_type', item);
    return locationType !== null && types.includes(asStr(locationType, 'lower').toLowerCase());
  }
  return false;
};

export const importItem = async (context: ImportContext, item: StixObject, update: boolean, types: string[] | null, bundleId: string) => {
  const operation = getAttributeInExtension('opencti_operation', item);
  if (pythonTruthy(getAttributeInExtension('is_inferred', item))) {
    return;
  }
  if (operation !== null) {
    await applyOpenctiOperation(context, item, operation, bundleId);
  } else if ('opencti_operation' in item) {
    await applyOpenctiOperation(context, item, item.opencti_operation, bundleId);
  } else if (item.type === 'relationship') {
    await importRelationship(context, item, update, types);
  } else if (item.type === 'sighting') {
    await importSightings(context, item, update);
  } else if (item.type === 'label') {
    await createLabel(context, {
      stix_id: item.id, value: required(item, 'value'), color: required(item, 'color'), x_opencti_stix_ids: getAttributeInExtension('stix_ids', item), update,
    });
  } else if (item.type === 'vocabulary') {
    await createVocabulary(context, {
      stix_id: item.id,
      name: required(item, 'name'),
      category: required(item, 'category'),
      description: field(item, 'description'),
      aliases: field(item, 'aliases'),
      x_opencti_stix_ids: getAttributeInExtension('stix_ids', item),
      update,
    });
  } else if (item.type === 'external-reference') {
    await createExternalReference(context, {
      stix_id: item.id,
      source_name: field(item, 'source_name'),
      url: field(item, 'url'),
      external_id: field(item, 'external_id'),
      description: field(item, 'description'),
      x_opencti_stix_ids: getAttributeInExtension('stix_ids', item),
      update,
    });
  } else if (item.type === 'kill-chain-phase') {
    await createKillChainPhase(context, {
      stix_id: item.id,
      kill_chain_name: required(item, 'kill_chain_name'),
      phase_name: required(item, 'phase_name'),
      x_opencti_order: field(item, 'order', 0),
      x_opencti_stix_ids: getAttributeInExtension('stix_ids', item),
      update,
    });
  } else if (isStixCyberObservableType(item.type)) {
    if (types === null || types.length === 0 || types.includes(item.type) || types.includes('observable')) {
      await importObservable(context, item, update, types);
    }
  } else if (item.type === 'marking-definition' || types === null || types.length === 0 || types.includes(item.type) || isInScope(item, types)) {
    await importObject(context, item, update, types);
  }
};
