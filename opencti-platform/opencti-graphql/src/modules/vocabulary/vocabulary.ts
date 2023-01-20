import vocabularyTypeDefs from './vocabulary.graphql';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import { ENTITY_TYPE_VOCABULARY, StixVocabulary, StoreEntityVocabulary, vocabularyDefinitions } from './vocabulary-types';
import vocabularyResolvers from './vocabulary-resolver';
import convertVocabularyToStix from './vocabulary-converter';
import { ABSTRACT_STIX_META_OBJECT } from '../../schema/general';

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
  graphql: {
    schema: vocabularyTypeDefs,
    resolver: vocabularyResolvers,
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
    { name: 'name', type: 'string', multiple: false, upsert: true },
    { name: 'description', type: 'string', multiple: false, upsert: true },
    { name: 'category', type: 'string', multiple: false, upsert: true },
  ],
  relations: [],
  depsKeys: generateInputDependencyKeys(),
  representative: (stix: StixVocabulary) => {
    return stix.name;
  },
  converter: convertVocabularyToStix,
};

registerDefinition(VOCABULARY_DEFINITION);
