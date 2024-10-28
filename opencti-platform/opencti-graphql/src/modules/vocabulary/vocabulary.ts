import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_VOCABULARY, type StixVocabulary, type StoreEntityVocabulary, vocabularyDefinitions } from './vocabulary-types';
import convertVocabularyToStix from './vocabulary-converter';
import { ABSTRACT_STIX_META_OBJECT } from '../../schema/general';
import { type ModuleDefinition, registerDefinition } from '../../schema/module';

const generateInputDependencyKeys = () => {
  return Object.values(vocabularyDefinitions)
    .flatMap(({ entity_types, fields }) => fields.map(({ key }) => ({ src: key, types: entity_types })));
};

const VOCABULARY_DEFINITION: ModuleDefinition<StoreEntityVocabulary, StixVocabulary> = {
  type: {
    id: 'vocabulary',
    name: ENTITY_TYPE_VOCABULARY,
    category: ABSTRACT_STIX_META_OBJECT,
    aliased: true
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_VOCABULARY]: [{ src: NAME_FIELD }, { src: 'category' }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'description', label: 'Description', type: 'string', format: 'text', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'category', label: 'Category', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    { name: 'order', label: 'Order', type: 'numeric', precision: 'integer', mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true },
    { name: 'builtIn', label: 'Is built-in', type: 'boolean', mandatoryType: 'no', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [],
  depsKeys: generateInputDependencyKeys(),
  representative: (stix: StixVocabulary) => {
    return stix.name;
  },
  converter: convertVocabularyToStix,
};

registerDefinition(VOCABULARY_DEFINITION);
