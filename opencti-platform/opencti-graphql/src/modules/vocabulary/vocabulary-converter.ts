import { buildStixObject, cleanObject } from '../../database/stix-2-1-converter';
import type { StixVocabulary, StoreEntityVocabulary } from './vocabulary-types';
import { STIX_EXT_OCTI } from '../../types/stix-2-1-extensions';

const convertVocabularyToStix = (instance: StoreEntityVocabulary): StixVocabulary => {
  const stixObject = buildStixObject(instance);
  return {
    ...stixObject,
    name: instance.name,
    description: instance.description,
    category: instance.category,
    aliases: instance.aliases ?? [],
    extensions: {
      [STIX_EXT_OCTI]: cleanObject({
        ...stixObject.extensions[STIX_EXT_OCTI],
        extension_type: 'new-sdo',
      })
    }
  };
};

export default convertVocabularyToStix;
