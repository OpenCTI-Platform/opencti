import convertLanguageToStix from './language-converter';
import { NAME_FIELD, normalizeName } from '../../schema/identifier';
import { ENTITY_TYPE_LANGUAGE } from './language-types';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../schema/general';
import { registerDefinition } from '../../schema/module';
const LANGUAGE_DEFINITION = {
    type: {
        id: 'languages',
        name: ENTITY_TYPE_LANGUAGE,
        category: ABSTRACT_STIX_DOMAIN_OBJECT,
        aliased: true
    },
    identifier: {
        definition: {
            [ENTITY_TYPE_LANGUAGE]: [{ src: NAME_FIELD }]
        },
        resolvers: {
            name(data) {
                return normalizeName(data);
            },
        },
    },
    attributes: [
        { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'external', editDefault: true, multiple: false, upsert: true, isFilterable: true },
    ],
    relations: [], // All relations are from the other side
    representative: (stix) => {
        return stix.name;
    },
    converter: convertLanguageToStix
};
registerDefinition(LANGUAGE_DEFINITION);
