import type { BasicStoreEntityVocabulary } from '../../../../src/modules/vocabulary/vocabulary-types';

// The way the platform creates its own entries (see openVocabularies): no description is '', no aliases [], no order 0
const storedVocabulary = {
  creator_id: ['creator-secret-id'],
  created_at: '2026-01-01T00:00:00.000Z',
  entity_type: 'Vocabulary',
  builtIn: false,
};

// An entry of the platform that nobody modified: exported like any other
export const defaultVocabulary = {
  ...storedVocabulary,
  id: 'default-vocabulary-id',
  internal_id: 'default-vocabulary-id',
  standard_id: 'vocabulary--11111111-2222-5333-8444-555555555555',
  name: 'threat-report',
  category: 'report_types_ov',
  description: '',
  aliases: [],
  order: 0,
} as unknown as BasicStoreEntityVocabulary;

// The only entry of its category the fixtures have, and nobody modified it: the category is exported all the same
export const untouchedVocabulary = {
  ...defaultVocabulary,
  id: 'untouched-vocabulary-id',
  internal_id: 'untouched-vocabulary-id',
  standard_id: 'vocabulary--99999999-8888-5777-8666-555555555555',
  name: 'alert',
  category: 'incident_type_ov',
  description: 'An alert.',
} as unknown as BasicStoreEntityVocabulary;

// An entry of the platform whose description was modified
export const modifiedVocabulary = {
  ...storedVocabulary,
  id: 'modified-vocabulary-id',
  internal_id: 'modified-vocabulary-id',
  standard_id: 'vocabulary--66666666-7777-5888-8999-aaaaaaaaaaaa',
  name: 'high',
  category: 'integrity_level_ov',
  description: 'Our own description of a high integrity',
  aliases: ['elevated'],
  order: 3,
} as unknown as BasicStoreEntityVocabulary;

// A custom entry
export const customVocabulary = {
  ...storedVocabulary,
  id: 'custom-vocabulary-id',
  internal_id: 'custom-vocabulary-id',
  standard_id: 'vocabulary--bbbbbbbb-cccc-5ddd-8eee-ffffffffffff',
  name: 'fimi-report',
  category: 'report_types_ov',
  description: 'Foreign information manipulation',
  aliases: ['fimi'],
  order: 5,
} as unknown as BasicStoreEntityVocabulary;

export const otherCustomVocabulary = {
  ...customVocabulary,
  id: 'other-custom-vocabulary-id',
  internal_id: 'other-custom-vocabulary-id',
  standard_id: 'vocabulary--00000000-1111-5222-8333-444444444444',
  name: 'sev-x',
  category: 'case_severity_ov',
  description: '',
  aliases: [],
  order: 0,
} as unknown as BasicStoreEntityVocabulary;

export const ALL_VOCABULARIES = [defaultVocabulary, untouchedVocabulary, modifiedVocabulary, customVocabulary, otherCustomVocabulary];
