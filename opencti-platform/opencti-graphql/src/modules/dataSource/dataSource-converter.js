import { buildStixDomain, cleanObject } from '../../database/stix-converter';
import { STIX_EXT_MITRE, STIX_EXT_OCTI } from '../../types/stix-extensions';
const convertDataSourceToStix = (instance) => {
    const stixDomainObject = buildStixDomain(instance);
    return Object.assign(Object.assign({}, stixDomainObject), { name: instance.name, description: instance.description, platforms: instance.x_mitre_platforms, collection_layers: instance.collection_layers, aliases: instance.aliases, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixDomainObject.extensions[STIX_EXT_OCTI]), { extension_type: 'property-extension' })),
            [STIX_EXT_MITRE]: {
                extension_type: 'new-sdo',
            }
        } });
};
export default convertDataSourceToStix;
