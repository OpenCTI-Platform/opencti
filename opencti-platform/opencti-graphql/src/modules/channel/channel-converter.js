import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixDomain, cleanObject } from '../../database/stix-converter';
const convertChannelToStix = (instance) => {
    var _a;
    const stixDomainObject = buildStixDomain(instance);
    return Object.assign(Object.assign({}, stixDomainObject), { name: instance.name, description: instance.description, channel_types: instance.channel_types, aliases: (_a = instance.x_opencti_aliases) !== null && _a !== void 0 ? _a : [], extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixDomainObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertChannelToStix;
