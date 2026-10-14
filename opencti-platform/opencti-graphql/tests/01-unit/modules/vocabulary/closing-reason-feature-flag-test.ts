import { afterAll, describe, expect, it } from 'vitest';

// Turn the dev features off before the modules register their attributes
const { ENABLED_FEATURE_FLAGS } = await import('../../../../src/config/conf');
const enabledFeatureFlags = ENABLED_FEATURE_FLAGS.splice(0, ENABLED_FEATURE_FLAGS.length);
await import('../../../../src/modules/index');
const { ENTITY_TYPE_CONTAINER_CASE_INCIDENT } = await import('../../../../src/modules/case/case-incident/case-incident-types');
const { getVocabulariesCategories, isEntityFieldAnOpenVocabulary } = await import('../../../../src/modules/vocabulary/vocabulary-utils');
const { schemaAttributesDefinition } = await import('../../../../src/schema/schema-attributes');
const { getVocabularyUsages } = await import('../../../../src/modules/vocabulary/vocabulary-domain');

describe('closing reason with the workflow engine disabled', () => {
  afterAll(() => {
    ENABLED_FEATURE_FLAGS.push(...enabledFeatureFlags);
  });

  it('should not register the x_opencti_closing_reason attribute', () => {
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_CONTAINER_CASE_INCIDENT, 'x_opencti_closing_reason')).toBeUndefined();
  });

  it('should hide the closing_reason_ov vocabulary category', () => {
    expect(getVocabulariesCategories().map(({ key }) => key)).not.toContain('closing_reason_ov');
    expect(isEntityFieldAnOpenVocabulary('x_opencti_closing_reason', ENTITY_TYPE_CONTAINER_CASE_INCIDENT)).toBe(false);
  });

  it('should count no usage for the values of the hidden category', async () => {
    const vocabulary = { name: 'duplicate', category: 'closing_reason_ov' } as any;
    await expect(getVocabularyUsages({} as any, {} as any, vocabulary)).resolves.toBe(0);
  });
});
