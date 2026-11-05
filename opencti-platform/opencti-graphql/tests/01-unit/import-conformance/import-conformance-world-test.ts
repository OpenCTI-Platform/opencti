import { describe, expect, it } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { getVocabulariesCategories } from '../../../src/modules/vocabulary/vocabulary-utils';

// The import conformance goldens are recorded by client-python against a declared world:
// what the platform answers to the reads of the STIX import. This test keeps that world in
// step with the platform. Regenerate with UPDATE_IMPORT_CONFORMANCE=true, then regenerate the
// goldens (client-python: python -m tests.import_conformance.generate).
const WORLD_DIR = join(__dirname, '../../../../../client-python/tests/data/import-conformance/world');

// Same selection as pycti's getVocabCategories query
const vocabularyCategories = () => getVocabulariesCategories().map(({ key, entity_types, fields }) => ({
  key,
  entity_types,
  fields: fields.map((field) => ({ key: field.key, required: field.required, multiple: field.multiple })),
}));

describe('Import conformance world', () => {
  it('should match the platform vocabulary categories', () => {
    const file = join(WORLD_DIR, 'vocabulary-categories.json');
    const current = vocabularyCategories();
    if (process.env.UPDATE_IMPORT_CONFORMANCE === 'true') {
      writeFileSync(file, `${JSON.stringify(current, null, 2)}\n`);
    }
    expect(JSON.parse(readFileSync(file, 'utf-8'))).toEqual(current);
  });
});
