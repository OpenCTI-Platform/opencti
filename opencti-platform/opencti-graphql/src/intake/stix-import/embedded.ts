import { getInCache, type ImportContext, setInCache } from './context';
import {
  createExternalReference,
  createKillChainPhase,
  externalReferenceKey,
  fileObjectsOf,
  filesInput,
  readOrCreateLabel,
  readOrCreateVocabulary,
  tlpClearMarking,
  vocabularyFields,
} from './sub-objects';
import { guessPastDate } from './dates';
import { createReport } from './entities/report';
import { resolveAuthor } from './author';
import { field } from './kwargs';
import { ImportClientError, type StixObject, StixImportError } from './types';
import { concat, contains, getAttributeInExtension, iterate, pythonStr, pythonTruthy, required } from './utils';

// pycti extract_embedded_relationships: the references of an object, with the sub-objects it
// creates first (labels, kill chain phases, external references, open vocabulary values)

export interface EmbeddedRelationships {
  created_by: unknown;
  object_marking: unknown;
  object_label: string[];
  open_vocabs: Record<string, unknown>;
  kill_chain_phases: string[];
  object_refs: unknown;
  granted_refs: unknown;
  sample_refs: unknown;
  external_references: string[];
  reports: Record<string, any>;
}

const EXTERNAL_REFERENCE_AS_REPORT_TYPES = ['threat-actor', 'intrusion-set', 'campaign', 'incident', 'malware', 'relationship'];
const EPOCH_PLUS_ONE_SECOND = '1970-01-01T00:00:01Z';

// Each entry is read when its turn comes (pycti reads a tag's value after the previous label)
const labelIds = async (context: ImportContext, entries: unknown[], read: (entry: any) => { value: unknown; color: unknown }) => {
  const ids: string[] = [];
  for (const entry of entries) {
    const { value, color } = read(entry);
    const key = concat('label_', value);
    const label = getInCache(context, key) ?? await readOrCreateLabel(context, value, color);
    if (label !== null && label !== undefined) {
      setInCache(context, key, label);
      ids.push(required(label, 'id'));
    }
  }
  return ids;
};

const killChainPhaseIds = async (context: ImportContext, phases: unknown) => {
  const ids: string[] = [];
  for (const phase of iterate(phases) as StixObject[]) {
    const key = concat(required(phase, 'kill_chain_name'), required(phase, 'phase_name'));
    let cached = getInCache(context, key);
    if (cached === null) {
      if (!contains(phase, 'x_opencti_order') && getAttributeInExtension('order', phase) !== null) {
        phase.x_opencti_order = getAttributeInExtension('order', phase);
      }
      const created = await createKillChainPhase(context, {
        kill_chain_name: phase.kill_chain_name,
        phase_name: phase.phase_name,
        x_opencti_order: field(phase, 'x_opencti_order', 0),
        stix_id: field(phase, 'id'),
      });
      cached = { id: required(created, 'id'), type: required(created, 'entity_type') };
      setInCache(context, key, cached);
    }
    ids.push(cached.id);
  }
  return ids;
};

// pycti `reference[key] if key in reference else None` (`in` on a str is a substring test)
const referenceValue = (reference: unknown, key: string) => (contains(reference, key) ? required(reference, key) : null);

const createReference = async (context: ImportContext, reference: StixObject) => {
  const created = await createExternalReference(context, {
    source_name: referenceValue(reference, 'source_name'),
    url: referenceValue(reference, 'url'),
    external_id: referenceValue(reference, 'external_id'),
    description: referenceValue(reference, 'description'),
    ...filesInput(fileObjectsOf(reference)),
  });
  return required(created, 'id');
};

// The report built from an external reference (types external-reference-as-report). pycti
// computes the title with str + str (TypeError on a non-str name) and str() of the external id.
const reportFromExternalReference = async (context: ImportContext, object: StixObject, reference: StixObject, referenceId: string) => {
  const sourceName = referenceValue(reference, 'source_name');
  let published = guessPastDate(contains(reference, 'description') ? required(reference, 'description') : sourceName, context.now) ?? EPOCH_PLUS_ONE_SECOND;
  let title: unknown;
  if (contains(sourceName, 'mitre') && 'name' in object) {
    title = concat('[MITRE ATT&CK] ', object.name);
    if ('modified' in object) {
      published = object.modified;
    }
  } else if (contains(sourceName, 'amitt') && 'name' in object) {
    title = concat('[AM!TT] ', object.name);
    if ('modified' in object) {
      published = object.modified;
    }
  } else {
    title = sourceName;
  }
  if (contains(reference, 'external_id')) {
    title = concat(concat(concat(title, ' ('), pythonStr(required(reference, 'external_id'))), ')');
  }
  const marking = await tlpClearMarking(context);
  const author = await resolveAuthor(context, title);
  return createReport(context, {
    name: title,
    createdBy: author !== null ? required(author, 'id') : null,
    objectMarking: [required(marking, 'id')],
    externalReferences: [referenceId],
    description: contains(reference, 'description') ? required(reference, 'description') : '',
    report_types: 'threat-report',
    published,
    update: true,
  });
};

const externalReferenceIds = async (context: ImportContext, object: StixObject, types: string[] | null, reports: Record<string, any>) => {
  const ids: string[] = [];
  if (object.external_references !== null && object.external_references !== undefined) {
    for (const reference of iterate(object.external_references) as StixObject[]) {
      // pycti catches any error of a reference (`except Exception`): the errors of the port are
      // its Python errors and the GraphQL errors, anything else is a defect of the port
      try {
        // generate_id is None: only the None matters, the key spares the uuid v5 of the id
        if (externalReferenceKey(referenceValue(reference, 'url'), referenceValue(reference, 'source_name'), referenceValue(reference, 'external_id')) === null) {
          continue;
        }
        const referenceId = await createReference(context, reference);
        ids.push(referenceId);
        if (EXTERNAL_REFERENCE_AS_REPORT_TYPES.includes(object.type) && types !== null && types.includes('external-reference-as-report')) {
          reports[referenceId] = await reportFromExternalReference(context, object, reference, referenceId);
        }
      } catch (error) {
        if (!(error instanceof StixImportError) && !(error instanceof ImportClientError)) {
          throw error;
        }
        context.logger.warn('Cannot generate external reference', { id: object.id, cause: error });
      }
    }
  } else if (object.x_opencti_external_references !== null && object.x_opencti_external_references !== undefined) {
    for (const reference of iterate(object.x_opencti_external_references) as StixObject[]) {
      if (externalReferenceKey(referenceValue(reference, 'url'), referenceValue(reference, 'source_name'), referenceValue(reference, 'external_id')) !== null) {
        ids.push(await createReference(context, reference));
      }
    }
  }
  return ids;
};

// The extras pycti's import methods build from the embedded relationships
export const embeddedExtras = (embedded: EmbeddedRelationships) => ({
  created_by_id: embedded.created_by,
  object_marking_ids: embedded.object_marking,
  object_label_ids: embedded.object_label,
  open_vocabs: embedded.open_vocabs,
  granted_refs_ids: embedded.granted_refs,
  kill_chain_phases_ids: embedded.kill_chain_phases,
  object_ids: embedded.object_refs,
  external_references_ids: embedded.external_references,
  reports: embedded.reports,
  sample_ids: embedded.sample_refs,
});

export const extractEmbeddedRelationships = async (context: ImportContext, object: StixObject, types: string[] | null = null): Promise<EmbeddedRelationships> => {
  // Created by: absent stays absent (undefined), unlike every other reference
  let createdBy: unknown;
  if ('created_by_ref' in object) {
    createdBy = object.created_by_ref;
  } else if ('x_opencti_created_by_ref' in object) {
    createdBy = object.x_opencti_created_by_ref;
  } else if (getAttributeInExtension('created_by_ref', object) !== null) {
    createdBy = getAttributeInExtension('created_by_ref', object);
  }
  const objectMarking = field(object, 'object_marking_refs');

  // Open vocabularies: only the fields of this object's entity type
  const openVocabularies: Record<string, unknown> = {};
  const fields = await vocabularyFields(context);
  // pycti `object.get("x_opencti_type") or get_attribute_in_extension("type") or object.get("type")`
  let entityType = field(object, 'x_opencti_type');
  if (!pythonTruthy(entityType)) {
    entityType = getAttributeInExtension('type', object);
  }
  if (!pythonTruthy(entityType)) {
    entityType = field(object, 'type');
  }
  const normalizedType = typeof entityType === 'string' ? entityType.toLowerCase() : null;
  const matchingFields = fields.filter((vocabularyField) => vocabularyField.key in object
    && ((normalizedType !== null && vocabularyField.lowerEntityTypes.includes(normalizedType)) || vocabularyField.entity_types.length === 0));
  for (const vocabularyField of matchingFields) {
    const value = object[vocabularyField.key];
    if (value === null || value === undefined) {
      continue;
    }
    // Python hasattr(value, "__len__") and len(value) == 0: an empty str, list or dict
    if ((typeof value === 'string' || Array.isArray(value)) && value.length === 0) {
      continue;
    }
    if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) {
      continue;
    }
    if (Array.isArray(value)) {
      openVocabularies[vocabularyField.key] = [];
      for (const vocabulary of value) {
        const resolved = await readOrCreateVocabulary(context, vocabulary, vocabularyField);
        if (resolved !== null && resolved !== undefined) {
          (openVocabularies[vocabularyField.key] as unknown[]).push(required(resolved, 'name'));
        }
      }
    } else {
      const resolved = await readOrCreateVocabulary(context, value, vocabularyField);
      if (resolved !== null && resolved !== undefined) {
        openVocabularies[vocabularyField.key] = required(resolved, 'name');
      }
    }
  }

  // Labels
  if (!('labels' in object) && getAttributeInExtension('labels', object) !== null) {
    object.labels = getAttributeInExtension('labels', object);
  }
  let objectLabel: string[] = [];
  if ('labels' in object) {
    objectLabel = await labelIds(context, iterate(object.labels), (value) => ({ value, color: null }));
  } else if ('x_opencti_labels' in object) {
    objectLabel = await labelIds(context, iterate(object.x_opencti_labels), (value) => ({ value, color: null }));
  } else if ('x_opencti_tags' in object) {
    objectLabel = await labelIds(context, iterate(object.x_opencti_tags), (tag) => ({ value: required(tag, 'value'), color: contains(tag, 'color') ? tag.color : null }));
  }

  // Kill chain phases
  if (!('kill_chain_phases' in object) && getAttributeInExtension('kill_chain_phases', object) !== null) {
    object.kill_chain_phases = getAttributeInExtension('kill_chain_phases', object);
  }
  let killChainPhases: string[] = [];
  if (object.kill_chain_phases !== null && object.kill_chain_phases !== undefined) {
    killChainPhases = await killChainPhaseIds(context, object.kill_chain_phases);
  } else if (object.x_opencti_kill_chain_phases !== null && object.x_opencti_kill_chain_phases !== undefined) {
    killChainPhases = await killChainPhaseIds(context, object.x_opencti_kill_chain_phases);
  }

  const objectRefs = field(object, 'object_refs', []);

  // External references
  if (!('external_references' in object) && getAttributeInExtension('external_references', object) !== null) {
    object.external_references = getAttributeInExtension('external_references', object);
  }
  const reports: Record<string, any> = {};
  const externalReferences = await externalReferenceIds(context, object, types, reports);

  // Granted refs
  let grantedRefs: unknown = [];
  if (!('x_opencti_granted_refs' in object) && getAttributeInExtension('granted_refs', object) !== null) {
    grantedRefs = getAttributeInExtension('granted_refs', object);
  } else if (object.x_opencti_granted_refs !== null && object.x_opencti_granted_refs !== undefined) {
    grantedRefs = object.x_opencti_granted_refs;
  }
  const sampleRefs = field(object, 'sample_refs', []);

  return {
    created_by: createdBy,
    object_marking: objectMarking,
    object_label: objectLabel,
    open_vocabs: openVocabularies,
    kill_chain_phases: killChainPhases,
    object_refs: objectRefs,
    granted_refs: grantedRefs,
    sample_refs: sampleRefs,
    external_references: externalReferences,
    reports,
  };
};
