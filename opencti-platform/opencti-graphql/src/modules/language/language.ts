import convertLanguageToStix, { convertLanguageToStix_2_0 } from './language-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_LANGUAGE, type Stix2Language, type StixLanguage, type StoreEntityLanguage } from './language-types';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import type { ModuleDefinition } from '../../schema/module';

export const LANGUAGE_DEFINITION: ModuleDefinition<StoreEntityLanguage, StixLanguage, Stix2Language> = {
  type: {
    id: 'languages',
    name: ENTITY_TYPE_LANGUAGE,
    category: ABSTRACT_STIX_DOMAIN_OBJECT,
    aliased: true,
  },
  identifier: {
    definition: {
      [ENTITY_TYPE_LANGUAGE]: [{ src: NAME_FIELD }],
    },
    resolvers: {
      name(data: object) {
        return normalizeName(data);
      },
    },
  },
  attributes: [
    { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
  ],
  relations: [], // All relations are from the other side
  representative: (stix: StixLanguage) => {
    return stix.name;
  },
  converter_2_1: convertLanguageToStix,
  converter_2_0: convertLanguageToStix_2_0,
};
