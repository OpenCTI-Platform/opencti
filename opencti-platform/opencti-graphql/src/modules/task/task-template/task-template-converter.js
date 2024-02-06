import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
const convertCaseTaskToStix = (instance) => {
    const caseTask = buildStixDomain(instance);
    return Object.assign(Object.assign({}, caseTask), { name: instance.name, description: instance.description, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, caseTask.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertCaseTaskToStix;
