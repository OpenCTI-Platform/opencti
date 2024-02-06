import { buildStixObject, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
const convertVocabularyToStix = (instance) => {
    var _a;
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { name: instance.name, description: instance.description, category: instance.category, aliases: (_a = instance.aliases) !== null && _a !== void 0 ? _a : [], extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertVocabularyToStix;
