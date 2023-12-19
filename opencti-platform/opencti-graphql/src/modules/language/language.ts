import languageTypeDefs from './language.graphql';
import convertLanguageToStix from './language-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import languageResolvers from './language-resolver';
import { ENTITY_TYPE_LANGUAGE, type StixLanguage, type StoreEntityLanguage } from './language-types';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';
import { registerDefinition } from '../../schema/module';

const LANGUAGE_DEFINITION: ModuleDefinition<StoreEntityLanguage, StixLanguage> = {
  type: {
    id: 'languages',
    name: ENTITY_TYPE_LANGUAGE,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: true
  },
  graphql: {
    schema: languageTypeDefs,
    resolver: languageResolvers,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_LANGUAGE]: [{ src: NAME_FIELD }]
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [], // All relations are from the other side
  representative: (stix: StixLanguage) => {
    return stix.name;
  },
  converter: convertLanguageToStix
};

registerDefinition(LANGUAGE_DEFINITION);
