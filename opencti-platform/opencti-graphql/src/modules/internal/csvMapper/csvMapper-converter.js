import { buildStixObject, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
const convertCsvMapperToStix = (instance) => {
    const stixObject = buildStixObject(instance);
    return Object.assign(Object.assign({}, stixObject), { name: instance.name, has_header: instance.has_header, separator: instance.separator, representations: instance.representations, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, stixObject.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertCsvMapperToStix;
