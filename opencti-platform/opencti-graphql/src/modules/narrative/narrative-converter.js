import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixDomain, cleanObject } from '../../database/stix-converter';
const convertNarrativeToStix = (instance) => {
    var _a, _b;
    const stixDomainObject = buildStixDomain(instance);
    return Object.assign(Object.assign({}, stixDomainObject), { name: instance.name, description: instance.description, aliases: (_a = instance.x_opencti_aliases) !== null && _a !== void 0 ? _a : [], narrative_types: (_b = instance.narrative_types) !== null && _b !== void 0 ? _b : [], extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixDomainObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertNarrativeToStix;
