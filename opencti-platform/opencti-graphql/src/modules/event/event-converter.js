import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixDomain, cleanObject, convertToStixDate } from '../../database/stix-converter';
const convertEventToStix = (instance) => {
    var _a;
    const stixDomainObject = buildStixDomain(instance);
    return Object.assign(Object.assign({}, stixDomainObject), { name: instance.name, description: instance.description, event_types: instance.event_types, start_time: convertToStixDate(instance.start_time), stop_time: convertToStixDate(instance.stop_time), aliases: (_a = instance.x_opencti_aliases) !== null && _a !== void 0 ? _a : [], extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixDomainObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertEventToStix;
