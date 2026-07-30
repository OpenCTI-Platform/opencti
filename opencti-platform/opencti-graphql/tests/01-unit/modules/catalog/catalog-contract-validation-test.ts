import { describe, expect, it, vi } from 'vitest';

import { validateManagerSupportedContract } from '../../../../src/modules/catalog/catalog-contract-validation';

describe('catalog-contract-validation', () => {
  it('returns early when contract is not manager-supported', () => {
    const compileValidator = vi.fn();
    const onMissingConfigSchema = vi.fn();

    expect(() => validateManagerSupportedContract({
      catalogId: 'catalog-1',
      contract: {
        title: 'Simple contract',
        slug: 'simple',
        manager_supported: false,
      },
      compileValidator,
      onMissingConfigSchema,
    })).not.toThrow();

    expect(compileValidator).not.toHaveBeenCalled();
    expect(onMissingConfigSchema).not.toHaveBeenCalled();
  });

  it('warns and skips validation when manager-supported contract has no config schema', () => {
    const compileValidator = vi.fn();
    const onMissingConfigSchema = vi.fn();

    expect(() => validateManagerSupportedContract({
      catalogId: 'catalog-1',
      contract: {
        title: 'Managed contract',
        slug: 'managed',
        manager_supported: true,
        container_image: 'opencti/managed:1.0.0',
        container_type: 'EXTERNAL_IMPORT',
      },
      compileValidator,
      onMissingConfigSchema,
    })).not.toThrow();

    expect(onMissingConfigSchema).toHaveBeenCalledWith('Managed contract');
    expect(compileValidator).not.toHaveBeenCalled();
  });

  it('throws when manager-supported contract is missing container_image', () => {
    const compileValidator = vi.fn();

    expect(() => validateManagerSupportedContract({
      catalogId: 'catalog-1',
      contract: {
        title: 'Broken contract',
        slug: 'broken',
        manager_supported: true,
        container_type: 'EXTERNAL_IMPORT',
        config_schema: {
          type: 'object',
          properties: { key: { type: 'string' } },
          required: ['key'],
          additionalProperties: false,
        },
      },
      compileValidator,
    })).toThrow('Contract must define container_image field');
  });

  it('throws when manager-supported contract is missing container_type', () => {
    const compileValidator = vi.fn();

    expect(() => validateManagerSupportedContract({
      catalogId: 'catalog-1',
      contract: {
        title: 'Broken contract',
        slug: 'broken',
        manager_supported: true,
        container_image: 'opencti/broken:1.0.0',
        config_schema: {
          type: 'object',
          properties: { key: { type: 'string' } },
          required: ['key'],
          additionalProperties: false,
        },
      },
      compileValidator,
    })).toThrow('Contract must define container_type field');
  });

  it('throws when config schema is invalid', () => {
    const compileValidator = vi.fn(() => {
      throw new Error('invalid schema');
    });

    expect(() => validateManagerSupportedContract({
      catalogId: 'catalog-1',
      contract: {
        title: 'Bad schema contract',
        slug: 'bad-schema',
        manager_supported: true,
        container_image: 'opencti/bad-schema:1.0.0',
        container_type: 'EXTERNAL_IMPORT',
        config_schema: {
          type: 'object',
          properties: { key: { type: 'not-a-type' } },
          required: ['key'],
          additionalProperties: false,
        },
      },
      compileValidator,
    })).toThrow('Contract must be a valid json schema definition');
  });

  it('compiles validator with expected cache key for valid manager-supported contract', () => {
    const compileValidator = vi.fn();

    expect(() => validateManagerSupportedContract({
      catalogId: 'catalog-1',
      contract: {
        title: 'Good contract',
        slug: 'good',
        manager_supported: true,
        container_image: 'opencti/good:1.0.0',
        container_type: 'EXTERNAL_IMPORT',
        config_schema: {
          type: 'object',
          properties: { key: { type: 'string' } },
          required: ['key'],
          additionalProperties: false,
        },
      },
      compileValidator,
    })).not.toThrow();

    expect(compileValidator).toHaveBeenCalledWith('catalog-contract:catalog-1:good', {
      type: 'object',
      properties: { key: { type: 'string' } },
      required: ['key'],
      additionalProperties: false,
    });
  });
});
