import { describe, expect, it } from 'vitest';

import { sanitizeManagerConfigSchema, shouldExcludeManagerConfigKey } from '../../../../src/modules/catalog/catalog-config-schema';

describe('catalog-config-schema', () => {
  it('shouldExcludeManagerConfigKey matches excluded keys case-insensitively', () => {
    expect(shouldExcludeManagerConfigKey('OPENCTI_TOKEN')).toBe(true);
    expect(shouldExcludeManagerConfigKey('opencti_url')).toBe(true);
    expect(shouldExcludeManagerConfigKey('OpenCtI_UrI')).toBe(true);
    expect(shouldExcludeManagerConfigKey('CONNECTOR_TYPE')).toBe(true);
    expect(shouldExcludeManagerConfigKey('connector_run_and_terminate')).toBe(true);
    expect(shouldExcludeManagerConfigKey('CUSTOM_VALUE')).toBe(false);
  });

  it('sanitizeManagerConfigSchema removes excluded keys from properties and required', () => {
    const schema = {
      type: 'object',
      additionalProperties: false,
      properties: {
        OPENCTI_TOKEN: { type: 'string' },
        opencti_url: { type: 'string' },
        OpenCtI_UrI: { type: 'string' },
        CONNECTOR_TYPE: { type: 'string' },
        connector_run_and_terminate: { type: 'string' },
        CUSTOM_API_KEY: { type: 'string' },
      },
      required: [
        'OPENCTI_TOKEN',
        'opencti_url',
        'OpenCtI_UrI',
        'CONNECTOR_TYPE',
        'connector_run_and_terminate',
        'CUSTOM_API_KEY',
      ],
    };

    const sanitized = sanitizeManagerConfigSchema(schema);

    expect(sanitized).toEqual(expect.objectContaining({
      additionalProperties: false,
      properties: {
        CUSTOM_API_KEY: { type: 'string' },
      },
      required: ['CUSTOM_API_KEY'],
    }));
  });

  it('sanitizeManagerConfigSchema tolerates invalid schema input', () => {
    const sanitized = sanitizeManagerConfigSchema(undefined);

    expect(sanitized.properties).toEqual({});
    expect(sanitized.required).toEqual([]);
  });
});
