import { buildStixDomain, cleanObject, convertObjectReferences, convertToStixDate } from '../../database/stix-converter';
import { INPUT_CREATED_BY, INPUT_OBJECTS } from '../../schema/general';
import { STIX_EXT_OCTI } from '../../types/stix-extensions';
const convertCaseTaskToStix = (instance) => {
    var _a, _b;
    const task = buildStixDomain(instance);
    return Object.assign(Object.assign({}, task), { name: instance.name, description: instance.description, due_date: convertToStixDate(instance.due_date), created_by_ref: (_a = instance[INPUT_CREATED_BY]) === null || _a === void 0 ? void 0 : _a.standard_id, object_refs: ((_b = instance[INPUT_OBJECTS]) !== null && _b !== void 0 ? _b : []).map((m) => m.standard_id), extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, task.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo', object_refs_inferred: convertObjectReferences(instance, true) }))
        } });
};
export default convertCaseTaskToStix;
