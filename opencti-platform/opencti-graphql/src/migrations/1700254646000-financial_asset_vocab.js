import { executionContext, SYSTEM_USER } from "../utils/access";
import { addVocabulary } from "../modules/vocabulary/vocabulary-domain";

const newVocabularies = {
  asset_type_ov: [
    { key: 'airplane', description: 'A winged vehicle capable of lifting itself off the earth' },
    { key: 'boat', description: 'A sea faring vessel' },
    { key: 'car', description: 'A motor vehicle with wheels' },
    { key: 'company', description: 'A company of financial value' },
    { key: 'domain_name' },
    { key: 'real_estate', description: 'Real property, houses, townhomes, etc.' },
    { key: 'digital', description: 'Digital assets such as NFTs' },
    { key: 'other', description: 'Another type of financial asset' },
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
      const data = { name: element.key, description: element.description, category: key, builtIn: false };
      await addVocabulary(context, SYSTEM_USER, data);
    }
  }
  next();
};

export const down = async (next) => {
  next();
};
