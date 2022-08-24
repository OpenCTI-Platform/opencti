import { STIX_EXT_OCTI } from '../../types/stix-extensions';
import { buildStixObject, cleanObject } from '../../database/stix-converter';
import type { StixLanguage, StoreEntityLanguage } from './language-types';
import { INPUT_CREATED_BY } from '../../schema/general';

const convertLanguageToStix = (instance: StoreEntityLanguage): StixLanguage => {
  const stixDomainObject = buildStixObject(instance);
  return {
    ...stixDomainObject,
    name: instance.name,
    aliases: instance.aliases ?? [],
    created_by_ref: instance[INPUT_CREATED_BY]?.standard_id,
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixDomainObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertLanguageToStix;
