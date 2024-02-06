import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
const convertCaseRftToStix = (instance) => {
    var _a;
    const caseRft = buildStixDomain(instance);
    return Object.assign(Object.assign({}, caseRft), { name: instance.name, description: instance.description, content: instance.content, content_mapping: instance.content_mapping, takedown_types: instance.takedown_types, severity: instance.severity, priority: instance.priority, object_refs: ((_a = instance[INPUT_OBJECTS]) !== null && _a !== void 0 ? _a : []).map((m) => m.standard_id), extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, caseRft.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertCaseRftToStix;
