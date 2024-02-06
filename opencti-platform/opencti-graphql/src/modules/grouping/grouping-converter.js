import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixDomain, cleanObject, convertObjectReferences } from '../../database/stix-converter';
import { INPUT_OBJECTS } from '../../schema/general';
const convertGroupingToStix = (instance) => {
    var _a;
    const grouping = buildStixDomain(instance);
    return Object.assign(Object.assign({}, grouping), { name: instance.name, description: instance.description, context: instance.context, object_refs: ((_a = instance[INPUT_OBJECTS]) !== null && _a !== void 0 ? _a : []).map((m) => m.standard_id), extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, grouping.extensions[STIX_EXT_OCTI]), { extension_type: 'property-extension', content: instance.content, content_mapping: instance.content_mapping, object_refs_inferred: convertObjectReferences(instance, true) }))
        } });
};
export default convertGroupingToStix;
