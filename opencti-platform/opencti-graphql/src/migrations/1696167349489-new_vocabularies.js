import { executionContext, SYSTEM_USER } from '../utils/access';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';

const newVocabularies = {
  gender_ov: [
    { key: 'male' },
    { key: 'female' },
    { key: 'nonbinary' },
    { key: 'other' },
  ],
  marital_status_ov: [
    { key: 'annulled' },
    { key: 'divorced' },
    { key: 'domestic_partner' },
    { key: 'legally_separated' },
    { key: 'separated' },
    { key: 'married' },
    { key: 'never_married' },
    { key: 'polygamous' },
    { key: 'single' },
    { key: 'widowed' },
  ],
  hair_color_ov: [
    { key: 'black' },
    { key: 'brown' },
    { key: 'blond' },
    { key: 'red' },
    { key: 'green' },
    { key: 'blue' },
    { key: 'gray' },
    { key: 'bald' },
    { key: 'other' },
  ],
  eye_color_ov: [
    { key: 'black' },
    { key: 'brown' },
    { key: 'green' },
    { key: 'blue' },
    { key: 'hazel' },
    { key: 'other' },
  ],
};

export const up = async (next) => {
  // Create new vocabularies
  const context = executionContext('migration');
  const vocabularyKeys = Object.keys(newVocabularies);
  for (let i = 0; i < vocabularyKeys.length; i += 1) {
    const key = vocabularyKeys[i];
    const elements = newVocabularies[key];
    for (let elementIndex = 0; elementIndex < elements.length; elementIndex += 1) {
      const element = elements[elementIndex];
      const data = { name: element.key, description: '', category: key, builtIn: false };
      await addVocabulary(context, SYSTEM_USER, data);
    }
  }
  next();
};

export const down = async (next) => {
  next();
};
