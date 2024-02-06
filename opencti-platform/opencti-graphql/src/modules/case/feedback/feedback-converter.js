import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import { INPUT_OBJECTS } from '../../../schema/general';
const convertFeedbackToStix = (instance) => {
    var _a;
    const feedback = buildStixDomain(instance);
    return Object.assign(Object.assign({}, feedback), { name: instance.name, description: instance.description, content: instance.content, content_mapping: instance.content_mapping, rating: instance.rating, object_refs: ((_a = instance[INPUT_OBJECTS]) !== null && _a !== void 0 ? _a : []).map((m) => m.standard_id), extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, feedback.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertFeedbackToStix;
