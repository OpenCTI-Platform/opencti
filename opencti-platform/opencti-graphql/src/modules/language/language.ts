import languageTypeDefs from './language.graphql';
import convertLanguageToStix from './language-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import languageResolvers from './language-resolver';
import { ENTITY_TYPE_LANGUAGE, StoreEntityLanguage } from './language-types';
import type { ModuleDefinition } from '../../types/module';
import { registerDefinition } from '../../types/module';

const LANGUAGE_DEFINITION: ModuleDefinition<StoreEntityLanguage> = {
  type: {
    id: 'languages',
    name: ENTITY_TYPE_LANGUAGE,
    category: 'StixDomainEntity',
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
  converter: convertLanguageToStix
};

registerDefinition(LANGUAGE_DEFINITION);
