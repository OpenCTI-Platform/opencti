import { afterAll, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elRawUpdateByQuery: vi.fn(),
}));
vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  deleteElementById: vi.fn(),
}));

// Turn the dev features off before the modules register their attributes
const { ENABLED_FEATURE_FLAGS } = await import('../../../../src/config/conf');
const enabledFeatureFlags = ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
await import('../../../../src/modules/index');
const { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } = await import('../../../../src/modules/case/case-incident/case-incident-types');
const { getVocabulariesCategories, getVocabularyCategory } = await import('../../../../src/modules/vocabulary/vocabulary-utils');
const { schemaAttributesDefinition } = await import('../../../../src/schema/schema-attributes');
const { deleteVocabulary, getVocabularyUsages } = await import('../../../../src/modules/vocabulary/vocabulary-domain');
const { storeLoadById } = await import('../../../../src/database/middleware-loader');
const { elRawUpdateByQuery } = await import('../../../../src/database/engine');

describe('closing reason with the workflow engine disabled', () => {
  afterAll(() => {
    ENABLED_FEATURE_FLAGS.push(...enabledFeatureFlags);
  });

  it('should not register the x_opencti_closing_reason attribute', () => {
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, 'x_opencti_closing_reason')).toBeUndefined();
  });

  it('should hide the closing_reason_ov vocabulary category', () => {
    expect(getVocabulariesCategories().map(({ key }) => key)).not.toContain('closing_reason_ov');
  });

  it('should still resolve the hidden category of its values', () => {
    expect(getVocabularyCategory('closing_reason_ov')).toMatchObject({ key: 'closing_reason_ov', closed: false });
  });

  it('should count no usage for the values of the hidden category', async () => {
    const vocabulary = { name: 'duplicate', category: 'closing_reason_ov' } as any;
    await expect(getVocabularyUsages({} as any, {} as any, vocabulary)).resolves.toBe(0);
  });

  // Entities closed while the flag was on still carry the value
  it('should clear a deleted value of the hidden category from the entities', async () => {
    (storeLoadById as any).mockResolvedValue({ id: 'vocabulary-id', name: 'duplicate', category: 'closing_reason_ov', builtIn: false });

    await deleteVocabulary({} as any, {} as any, 'vocabulary-id');

    const { params } = (elRawUpdateByQuery as any).mock.calls[0][0].body.script;
    expect(params).toMatchObject({ oldName: 'duplicate', category: { key: 'closing_reason_ov', fields: [{ key: 'x_opencti_closing_reason' }] } });
  });
});
