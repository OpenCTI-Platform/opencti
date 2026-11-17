import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';
import { buildStixObject } from '../../database/stix-2-1-converter';
import { ENTITY_TYPE_LANGUAGE, type Stix2Language, type StixLanguage, type StoreEntityLanguage } from './language-types';
import { INPUT_CREATED_BY } from '../../schema/general';
import { assertType, cleanObject } from '../../database/stix-converter-utils';
import { buildStixDomain as buildStixDomain2 } from '../../database/stix-2-0-converter';

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
      }),
    },
  };
};

export const convertLanguageToStix_2_0 = (instance: StoreEntityLanguage): Stix2Language => {
  assertType(ENTITY_TYPE_LANGUAGE, instance.entity_type);
  const language = buildStixDomain2(instance);
  return {
    ...language,
    name: instance.name,
    aliases: instance.aliases ?? [],
  };
};

export default convertLanguageToStix;
