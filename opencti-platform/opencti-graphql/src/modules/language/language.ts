import languageTypeDefs from './language.graphql';
import convertLanguageToStix from './language-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import languageResolvers from './language-resolver';
import { ENTITY_TYPE_LANGUAGE, StixLanguage, StoreEntityLanguage } from './language-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';

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
    { name: 'name', type: 'string', multiple: false, upsert: true },
  ],
  relations: [], // All relations are from the other side
  representative: (stix: StixLanguage) => {
    return stix.name;
  },
  converter: convertLanguageToStix
};

registerDefinition(LANGUAGE_DEFINITION);
