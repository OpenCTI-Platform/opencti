import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
const convertCaseTemplateToStix = (instance) => {
    const caseTemplate = buildStixDomain(instance);
    return Object.assign(Object.assign({}, caseTemplate), { name: instance.name, description: instance.description, extensions: {
            [STIX_EXT_OCTI]: cleanObject(Object.assign(Object.assign({}, caseTemplate.extensions[STIX_EXT_OCTI]), { extension_type: 'new-sdo' }))
        } });
};
export default convertCaseTemplateToStix;
