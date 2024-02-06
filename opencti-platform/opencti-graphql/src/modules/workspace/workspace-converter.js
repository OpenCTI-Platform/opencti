import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixDomain, cleanObject, convertObjectReferences } from '../../database/stix-converter';
const convertWorkspaceToStix = (instance) => {
    var _a, _b;
    const stixDomainObject = buildStixDomain(instance);
    return Object.assign(Object.assign({}, stixDomainObject), { name: instance.name, description: instance.description, type: instance.type, graph_data: instance.graph_data, manifest: instance.manifest, tags: (_a = instance.tags) !== null && _a !== void 0 ? _a : [], object_refs: convertObjectReferences(instance), aliases: (_b = instance.x_opencti_aliases) !== null && _b !== void 0 ? _b : [], extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixDomainObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo', object_refs_inferred: convertObjectReferences(instance, true) }))
        } });
};
export default convertWorkspaceToStix;
