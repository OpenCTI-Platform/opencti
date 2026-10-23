import { describe, expect, it } from 'vitest';
import { getVocabularyCategoryForField, isEntityFieldAnOpenVocabulary } from '../../../../src/modules/vocabulary/vocabulary-utils';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';

describe('Vocabulary of a field', () => {
  it('should tell whether a field of a type is an open vocabulary, the same every time', () => {
    for (let call = 0; call < 2; call += 1) {
      expect(isEntityFieldAnOpenVocabulary('malware_types', ENTITY_TYPE_MALWARE)).toBe(true);
      expect(isEntityFieldAnOpenVocabulary('name', ENTITY_TYPE_MALWARE)).toBe(false);
      expect(isEntityFieldAnOpenVocabulary('malware_types', 'Unknown-Type')).toBe(false);
    }
  });
  it('should give the category of a field, the same every time', () => {
    for (let call = 0; call < 2; call += 1) {
      const { category, field } = getVocabularyCategoryForField('malware_types', ENTITY_TYPE_MALWARE);
      expect(category).toBe('malware_type_ov');
      expect(field?.key).toBe('malware_types');
    }
    expect(() => getVocabularyCategoryForField('name', ENTITY_TYPE_MALWARE)).toThrow();
  });
});
