import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import { INPUT_DATA_SOURCE } from './dataComponent-types';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
const convertDataComponentToStix = (instance) => {
    var _a;
    const stixDomainObject = buildStixDomain(instance);
    return Object.assign(Object.assign({}, stixDomainObject), { name: instance.name, description: instance.description, aliases: instance.aliases, data_source_ref: (_a = instance[INPUT_DATA_SOURCE]) === null || _a === void 0 ? void 0 : _a.standard_id, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixDomainObject.extensions[STIX_EXT_OCTI]), { extension_type: 'property-extension' })),
            [STIX_EXT_MITRE]: {
                extension_type: 'new-sdo',
            }
        } });
};
export default convertDataComponentToStix;
