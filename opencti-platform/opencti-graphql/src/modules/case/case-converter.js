import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import { INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
const convertCaseToStix = (instance) => {
    var _a;
    const cases = buildStixDomain(instance);
    return Object.assign(Object.assign(Object.assign({}, instance), cases), { object_refs: ((_a = instance[INPUT_OBJECTS]) !== null && _a !== void 0 ? _a : []).map((m) => m.standard_id), extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, cases.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertCaseToStix;
