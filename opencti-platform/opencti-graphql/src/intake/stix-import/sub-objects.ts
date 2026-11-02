import jsonCanonicalize from 'canonicalize';
import { v5 as uuidv5 } from 'uuid';
import { OASIS_NAMESPACE } from '../../schema/general';
import { getInCache, type ImportContext, setInCache } from './context';
import { ImportClientError, type StixObject, StixImportError, UploadFile } from './types';
import { b64decode, contains, dictGet, getAttributeInExtension, iterate, pythonStr, required } from './utils';
import { kw, type Kwargs } from './kwargs';

// Calls pycti makes to resolve or create the sub-objects of an imported object
// (pycti/entities/opencti_label.py, opencti_vocabulary.py, opencti_kill_chain_phase.py,
// opencti_external_reference.py, opencti_marking_definition.py)

// pycti process_multiple: the nodes of a connection
export const nodesOf = (connection: any): any[] => (connection?.edges ?? []).map((edge: any) => edge.node);

const valueFilter = (key: string, value: unknown) => ({ mode: 'and', filters: [{ key, values: [value] }], filterGroups: [] });

const LABELS_QUERY = `
  query Labels($filters: FilterGroup, $search: String, $first: Int, $after: ID, $orderBy: LabelsOrdering, $orderMode: OrderingMode) {
    labels(filters: $filters, search: $search, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
      edges { node { id standard_id value color } }
    }
  }
`;
const LABEL_ADD = `
  mutation LabelAdd($input: LabelAddInput!) {
    labelAdd(input: $input) { id standard_id value color }
  }
`;

// pycti `except ValueError`: a GraphQL error (pycti's query raises ValueError) or a ValueError of
// the port (binascii.Error is one)
const isPythonValueError = (error: unknown) => error instanceof ImportClientError
  || (error instanceof StixImportError && (error.name === 'ValueError' || error.name === 'Error'));

// pycti `try: return self.create(**kwargs) except ValueError: return None` (read_or_create_unchecked)
const createUnchecked = async (create: () => Promise<any>) => {
  try {
    return await create();
  } catch (error) {
    if (isPythonValueError(error)) {
      return null;
    }
    throw error;
  }
};

// pycti label.create
export const createLabel = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'value') === null) {
    context.logger.error('[opencti_label] Missing parameters: value');
    return null;
  }
  const data = await context.client.query(LABEL_ADD, {
    input: {
      stix_id: kw(kwargs, 'stix_id'), value: kw(kwargs, 'value'), color: kw(kwargs, 'color'), x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'), update: kw(kwargs, 'update', false),
    },
  });
  return data.labelAdd;
};

// pycti label.read_or_create_unchecked
export const readOrCreateLabel = async (context: ImportContext, value: unknown, color: unknown = null) => {
  const data = await context.client.query(LABELS_QUERY, {
    filters: valueFilter('value', value), search: null, first: 500, after: null, orderBy: null, orderMode: null,
  });
  const existing = nodesOf(data.labels)[0];
  if (existing !== undefined) {
    return existing;
  }
  return createUnchecked(() => createLabel(context, { value, color }));
};

const VOCABULARIES_QUERY = `
  query Vocabularies($filters: FilterGroup) {
    vocabularies(filters: $filters) {
      edges { node { id standard_id name category { key } } }
    }
  }
`;
const VOCABULARY_ADD = `
  mutation VocabularyAdd($input: VocabularyAddInput!) {
    vocabularyAdd(input: $input) { id standard_id name category { key } }
  }
`;

export interface VocabularyField {
  key: string;
  required: boolean;
  multiple: boolean;
  category: string;
  entity_types: string[];
  // entity_types in lower case, computed once (pycti lowers them for each object)
  lowerEntityTypes: string[];
}

// pycti vocabulary.create
export const createVocabulary = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'name') === null || kw(kwargs, 'category') === null) {
    context.logger.error('[opencti_vocabulary] Missing parameters: name or category');
    return null;
  }
  const data = await context.client.query(VOCABULARY_ADD, {
    input: {
      stix_id: kw(kwargs, 'stix_id'),
      x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
      name: kw(kwargs, 'name'),
      description: kw(kwargs, 'description'),
      category: kw(kwargs, 'category'),
      created: kw(kwargs, 'created'),
      modified: kw(kwargs, 'modified'),
      aliases: kw(kwargs, 'aliases'),
      update: kw(kwargs, 'update', false),
    },
  });
  return data.vocabularyAdd;
};

// pycti vocabulary.read_or_create_unchecked_with_cache (cache = permanent cache); the field always
// has its category, so pycti's fallback on the cached category is never used
export const readOrCreateVocabulary = async (context: ImportContext, name: unknown, field: VocabularyField) => {
  const { category } = field;
  // pycti f-string: str() of the value
  const cacheKey = `vocab_${pythonStr(category)}_${pythonStr(name)}`;
  let vocabulary = context.permanentCache.get(cacheKey);
  if (!context.permanentCache.has(cacheKey)) {
    // pycti vocabulary.read_or_create_unchecked
    const data = await context.client.query(VOCABULARIES_QUERY, { filters: valueFilter('name', name) });
    vocabulary = nodesOf(data.vocabularies)[0] ?? null;
    if (vocabulary === null) {
      vocabulary = await createUnchecked(() => createVocabulary(context, { name, required: field.required, category }));
    }
  }
  if (vocabulary !== null && vocabulary !== undefined) {
    context.permanentCache.set(cacheKey, vocabulary);
  }
  return vocabulary;
};

const VOCABULARY_CATEGORIES_QUERY = `
  query getVocabCategories {
    vocabularyCategories { key entity_types fields { key required multiple } }
  }
`;

// The open vocabulary fields, read once per importer
export const vocabularyFields = async (context: ImportContext): Promise<VocabularyField[]> => {
  const key = 'vocabularies_definition_fields';
  if (!context.permanentCache.has(key)) {
    const fields: VocabularyField[] = [];
    context.permanentCache.set(key, fields);
    const data = await context.client.query(VOCABULARY_CATEGORIES_QUERY);
    data.vocabularyCategories.forEach((category: any) => {
      category.fields.forEach((field: any) => {
        fields.push({
          key: field.key,
          required: field.required,
          multiple: field.multiple,
          category: category.key,
          entity_types: category.entity_types,
          lowerEntityTypes: category.entity_types.map((type: string) => type.toLowerCase()),
        });
      });
    });
  }
  return context.permanentCache.get(key);
};

const KILL_CHAIN_PHASE_ADD = `
  mutation KillChainPhaseAdd($input: KillChainPhaseAddInput!) {
    killChainPhaseAdd(input: $input) { id standard_id entity_type kill_chain_name phase_name x_opencti_order }
  }
`;

// pycti kill_chain_phase.create
export const createKillChainPhase = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'kill_chain_name') === null || kw(kwargs, 'phase_name') === null) {
    context.logger.error('[opencti_kill_chain_phase] Missing parameters: kill_chain_name and phase_name');
    return null;
  }
  const data = await context.client.query(KILL_CHAIN_PHASE_ADD, {
    input: {
      stix_id: kw(kwargs, 'stix_id'),
      created: kw(kwargs, 'created'),
      modified: kw(kwargs, 'modified'),
      kill_chain_name: kw(kwargs, 'kill_chain_name'),
      phase_name: kw(kwargs, 'phase_name'),
      x_opencti_order: kw(kwargs, 'x_opencti_order', 0),
      update: kw(kwargs, 'update', false),
    },
  });
  return data.killChainPhaseAdd;
};

// The canonical JSON pycti external_reference.generate_id hashes (None checks, not
// truthiness), null when it gives no id. It throws as externalReferenceId does: a lone
// surrogate or a non-finite number cannot be canonicalized.
export const externalReferenceKey = (url: unknown, sourceName: unknown, externalId: unknown) => {
  let data: Record<string, unknown>;
  if (url !== null && url !== undefined) {
    data = { url };
  } else if (sourceName !== null && sourceName !== undefined && externalId !== null && externalId !== undefined) {
    data = { source_name: sourceName, external_id: externalId };
  } else {
    return null;
  }
  return jsonCanonicalize(data) as string;
};

// pycti external_reference.generate_id
export const externalReferenceId = (url: unknown, sourceName: unknown, externalId: unknown) => {
  const key = externalReferenceKey(url, sourceName, externalId);
  return key === null ? null : `external-reference--${uuidv5(key, OASIS_NAMESPACE)}`;
};

const EXTERNAL_REFERENCE_ADD = `
  mutation ExternalReferenceAdd($input: ExternalReferenceAddInput!) {
    externalReferenceAdd(input: $input) { id standard_id entity_type source_name url external_id }
  }
`;

export interface FilesInput {
  files: UploadFile[] | null;
  filesMarkings: unknown[] | null;
  noTriggerImport: unknown[] | null;
  embedded: unknown[] | null;
}

// The files an object carries: x_opencti_files, then the extension files (pycti list.extend)
export const fileObjectsOf = (object: StixObject): StixObject[] => {
  const fileObjects: StixObject[] = [];
  if (contains(object, 'x_opencti_files')) {
    fileObjects.push(...iterate(required(object, 'x_opencti_files')) as StixObject[]);
  }
  const extensionFiles = getAttributeInExtension('files', object);
  if (extensionFiles !== null) {
    fileObjects.push(...iterate(extensionFiles) as StixObject[]);
  }
  return fileObjects;
};

// Files carried by an object (x_opencti_files and the extension files), uploaded with its creation.
// pycti decodes `file_obj["data"]` when the key is there (a None fails in b64decode), and reads
// `file_obj["name"]` without a guard.
export const filesInput = (fileObjects: StixObject[]): FilesInput => {
  const files: UploadFile[] = [];
  const filesMarkings: unknown[] = [];
  const noTriggerImport: unknown[] = [];
  const embedded: unknown[] = [];
  fileObjects.forEach((file) => {
    if (contains(file, 'data')) {
      const data = b64decode(required(file, 'data'));
      files.push(new UploadFile(required(file, 'name'), data, dictGet(file, 'mime_type', 'application/octet-stream')));
      filesMarkings.push(dictGet(file, 'object_marking_refs'));
      noTriggerImport.push(dictGet(file, 'no_trigger_import', false));
      embedded.push(dictGet(file, 'embedded', false));
    }
  });
  return {
    files: files.length > 0 ? files : null,
    filesMarkings: filesMarkings.length > 0 ? filesMarkings : null,
    noTriggerImport: noTriggerImport.length > 0 ? noTriggerImport : null,
    embedded: embedded.length > 0 ? embedded : null,
  };
};

// pycti external_reference.create
export const createExternalReference = async (context: ImportContext, kwargs: Kwargs) => {
  if (kw(kwargs, 'source_name') === null && kw(kwargs, 'url') === null) {
    context.logger.error('[opencti_external_reference] Missing parameters: source_name and url');
    return null;
  }
  const data = await context.client.query(EXTERNAL_REFERENCE_ADD, {
    input: {
      stix_id: kw(kwargs, 'stix_id'),
      created: kw(kwargs, 'created'),
      modified: kw(kwargs, 'modified'),
      source_name: kw(kwargs, 'source_name'),
      external_id: kw(kwargs, 'external_id'),
      description: kw(kwargs, 'description'),
      url: kw(kwargs, 'url'),
      x_opencti_stix_ids: kw(kwargs, 'x_opencti_stix_ids'),
      update: kw(kwargs, 'update', false),
      files: kw(kwargs, 'files'),
      filesMarkings: kw(kwargs, 'filesMarkings'),
      noTriggerImport: kw(kwargs, 'noTriggerImport'),
      embedded: kw(kwargs, 'embedded'),
    },
  });
  return data.externalReferenceAdd;
};

const MARKING_DEFINITIONS_QUERY = `
  query MarkingDefinitions($filters: FilterGroup, $first: Int, $after: ID, $orderBy: MarkingDefinitionsOrdering, $orderMode: OrderingMode) {
    markingDefinitions(filters: $filters, first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode) {
      edges { node { id standard_id entity_type definition_type definition } }
    }
  }
`;

// The TLP:CLEAR marking, read once (pycti cache key marking_tlpclear)
export const tlpClearMarking = async (context: ImportContext) => {
  const cached = getInCache(context, 'marking_tlpclear');
  if (cached !== null) {
    return cached;
  }
  const data = await context.client.query(MARKING_DEFINITIONS_QUERY, {
    filters: {
      mode: 'and',
      filters: [{ key: 'definition_type', values: ['TLP'] }, { key: 'definition', values: ['TLP:CLEAR'] }],
      filterGroups: [],
    },
    first: 500,
    after: null,
    orderBy: null,
    orderMode: null,
  });
  const marking = nodesOf(data.markingDefinitions)[0] ?? null;
  // pycti caches the id of the marking: TypeError when it is not found (caught by the caller)
  setInCache(context, 'marking_tlpclear', { id: required(marking, 'id') });
  return marking;
};
