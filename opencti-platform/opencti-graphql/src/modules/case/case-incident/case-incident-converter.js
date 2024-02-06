import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
const convertCaseIncidentToStix = (instance) => {
    var _a;
    const caseIncident = buildStixDomain(instance);
    return Object.assign(Object.assign({}, caseIncident), { name: instance.name, description: instance.description, content: instance.content, content_mapping: instance.content_mapping, severity: instance.severity, priority: instance.priority, response_types: instance.response_types, object_refs: ((_a = instance[INPUT_OBJECTS]) !== null && _a !== void 0 ? _a : []).map((m) => m.standard_id), extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, caseIncident.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertCaseIncidentToStix;
