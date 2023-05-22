import { buildStixDomain, cleanObject } from '../../../database/stix-converter';
import { STIX_EXT_OCTI } from '../../../types/stix-extensions';
import type { StixCaseTemplate, StoreEntityCaseTemplate } from './case-template-types';

const convertCaseTemplateToStix = (instance: StoreEntityCaseTemplate): StixCaseTemplate => {
  const caseTemplate = buildStixDomain(instance);
  return {
    ...caseTemplate,
    name: instance.name,
    description: instance.description,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...caseTemplate.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertCaseTemplateToStix;
