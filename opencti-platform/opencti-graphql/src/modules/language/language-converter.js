import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import { INPUT_CREATED_BY } from '../../schema/general';
const convertLanguageToStix = (instance) => {
    var _a, _b;
    const stixDomainObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixDomainObject), { name: instance.name, aliases: (_a = instance.aliases) !== null && _a !== void 0 ? _a : [], created_by_ref: (_b = instance[INPUT_CREATED_BY]) === null || _b === void 0 ? void 0 : _b.standard_id, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixDomainObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertLanguageToStix;
