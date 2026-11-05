import { field } from './kwargs';
import { type ImportContext, setInCache } from './context';
import { extractEmbeddedRelationships } from './embedded';
import { fileObjectsOf, filesInput } from './sub-objects';
import { createStixCyberObservable } from './observables-create';
import { createStixNestedRefRelationship } from './observables-refs';
import type { StixObject } from './types';
import { getAttributeInExtension, iterate, pythonInt, required } from './utils';

// pycti OpenCTIStix2.import_observable (pycti/utils/opencti_stix2.py)

// pycti OBSERVABLES_VALUE_INT (pycti/utils/opencti_stix2_utils.py): simple observable keys whose
// value is converted with int()
const OBSERVABLES_VALUE_INT = ['Autonomous-System.number', 'Network-Traffic.dst_port', 'Process.pid'];

// Keys never turned into nested ref relationships
const EXCLUDED_REF_KEYS = ['created_by_ref', 'object_marking_refs', 'x_opencti_created_by_ref', 'x_opencti_granted_refs', 'src_ref', 'dst_ref'];

// The relationship type of a ref key without its suffix: dashes, but x_opencti_ kept as is
const refRelationshipType = (key: string, suffix: string) => {
  // Python str.replace: every occurrence
  const relationshipType = key.replaceAll(suffix, '');
  if (relationshipType.startsWith('x_opencti_')) {
    return `x_opencti_${relationshipType.slice('x_opencti_'.length).replaceAll('_', '-')}`;
  }
  return relationshipType.replaceAll('_', '-');
};

export const importObservable = async (context: ImportContext, stixObject: StixObject, update: boolean, types: string[] | null) => {
  const embedded = await extractEmbeddedRelationships(context, stixObject, types);
  const { files, filesMarkings, noTriggerImport, embedded: embeddedFlags } = filesInput(fileObjectsOf(stixObject));
  const upsertOperations = getAttributeInExtension('opencti_upsert_operations', stixObject);
  // The extras pycti reads (all present in its extras dict)
  const common = {
    createdBy: embedded.created_by,
    objectMarking: embedded.object_marking,
    objectLabel: embedded.object_label,
    externalReferences: embedded.external_references,
    objectOrganization: embedded.granted_refs,
    update,
    files,
    filesMarkings,
    noTriggerImport,
    embedded: embeddedFlags,
    upsert_operations: upsertOperations,
  };
  let result: any;
  if (stixObject.type === 'simple-observable') {
    result = await createStixCyberObservable(context, {
      simple_observable_id: stixObject.id,
      simple_observable_key: required(stixObject, 'key'),
      simple_observable_value: OBSERVABLES_VALUE_INT.includes(required(stixObject, 'key')) ? pythonInt(required(stixObject, 'value')) : required(stixObject, 'value'),
      simple_observable_description: field(stixObject, 'description'),
      x_opencti_score: field(stixObject, 'x_opencti_score'),
      createIndicator: field(stixObject, 'x_opencti_create_indicator'),
      ...common,
    });
  } else {
    result = await createStixCyberObservable(context, { observableData: stixObject, ...common });
  }
  if (result === null || result === undefined) {
    return null;
  }
  const cached = { id: result.id, type: result.entity_type };
  if ('id' in stixObject) {
    setInCache(context, stixObject.id, cached);
  }
  setInCache(context, result.id, { ...cached });
  // The refs of the object become nested ref relationships, in the order of its keys
  for (const key of Object.keys(stixObject)) {
    if (EXCLUDED_REF_KEYS.includes(key)) {
      continue;
    }
    if (key.endsWith('_ref')) {
      await createStixNestedRefRelationship(context, { fromId: result.id, toId: stixObject[key], relationship_type: refRelationshipType(key, '_ref') });
    } else if (key.endsWith('_refs')) {
      const relationshipType = refRelationshipType(key, '_refs');
      for (const value of iterate(stixObject[key])) {
        await createStixNestedRefRelationship(context, { fromId: result.id, toId: value, relationship_type: relationshipType });
      }
    }
  }
  return null;
};
