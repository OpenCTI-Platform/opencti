import { describe, expect, it } from 'vitest';
import type { CatalogContract } from '../../../../src/modules/catalog/catalog-types';
import { computeCatalogContractLogoUploadOperation, getMimeTypeFromImageExtension } from '../../../../src/modules/catalog/catalog-logo-storage';

const buildContract = (logo: string | null): CatalogContract => ({
  title: 'Contract title',
  slug: 'contract-slug',
  description: 'description',
  short_description: 'short description',
  logo,
  use_cases: [],
  verified: true,
  last_verified_date: '2024-01-01',
  playbook_supported: false,
  max_confidence_level: 50,
  support_version: '6.7.0',
  subscription_link: null,
  source_code: '',
  manager_supported: true,
  container_version: '1.2.3',
  container_image: 'opencti/connector-test',
  container_type: 'EXTERNAL_IMPORT',
  config_schema: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'id',
    type: 'object',
    properties: {},
    required: [],
    additionalProperties: true,
  },
  license_type: null,
  solution_categories: [],
  contact: null,
});

describe('catalog-logo-storage', () => {
  it('should return no-logo when contract has no logo', () => {
    const result = computeCatalogContractLogoUploadOperation(buildContract(null), new Set<string>());
    expect(result).toEqual({ result: 'no-logo', logoUri: null });
  });

  it('should reject non data URL logos', () => {
    const result = computeCatalogContractLogoUploadOperation(buildContract('https://example.org/logo.png'), new Set<string>());
    expect(result.result).toBe('failed');
    if (result.result === 'failed') {
      expect(result.error.message).toContain('not a data URL');
    }
  });

  it('should reject unsupported mime type', () => {
    const result = computeCatalogContractLogoUploadOperation(buildContract('data:text/plain;base64,Zm9v'), new Set<string>());
    expect(result.result).toBe('failed');
    if (result.result === 'failed') {
      expect(result.error.message).toContain('Unsupported logo mime type');
    }
  });

  it('should reject invalid base64 payload', () => {
    const result = computeCatalogContractLogoUploadOperation(buildContract('data:image/png;base64,not-valid-***'), new Set<string>());
    expect(result.result).toBe('failed');
    if (result.result === 'failed') {
      expect(result.error.message).toContain('invalid base64 payload');
    }
  });

  it('should reject invalid URL-encoded payload', () => {
    const result = computeCatalogContractLogoUploadOperation(buildContract('data:image/svg+xml,%E0%A4%A'), new Set<string>());
    expect(result.result).toBe('failed');
    if (result.result === 'failed') {
      expect(result.error.message).toContain('invalid URL-encoded payload');
    }
  });

  it('should reject zero-length payload', () => {
    const result = computeCatalogContractLogoUploadOperation(buildContract('data:image/svg+xml,'), new Set<string>());
    expect(result.result).toBe('failed');
    if (result.result === 'failed') {
      expect(result.error.message).toContain('Unexpected zero-length logo data');
    }
  });

  it('should return dedup success when logo already exists', () => {
    const first = computeCatalogContractLogoUploadOperation(buildContract('data:image/png;base64,Zm9v'), new Set<string>());
    expect(first.result).toBe('success');
    if (first.result !== 'success') {
      return;
    }
    const second = computeCatalogContractLogoUploadOperation(
      buildContract('data:image/png;base64,Zm9v'),
      new Set<string>([first.filename]),
    );
    expect(second).toEqual({
      result: 'success',
      existed: true,
      logoUri: first.logoUri,
      filename: first.filename,
    });
  });

  it('should build upload operation for base64 payload', () => {
    const result = computeCatalogContractLogoUploadOperation(buildContract('data:image/png;base64,Zm9v'), new Set<string>());
    expect(result.result).toBe('success');
    if (result.result !== 'success') {
      return;
    }
    expect(result.existed).toBe(false);
    expect(result.filename.endsWith('.png')).toBe(true);
    expect(result.logoUri).toContain('/catalog/logo/');
    expect(result.operation?.s3Key).toContain('catalog-logos/');
    expect(result.operation?.body.toString('utf8')).toBe('foo');
  });

  it('should build upload operation for URL-encoded payload', () => {
    const result = computeCatalogContractLogoUploadOperation(buildContract('data:image/svg+xml,%3Csvg%3Eok%3C%2Fsvg%3E'), new Set<string>());
    expect(result.result).toBe('success');
    if (result.result !== 'success') {
      return;
    }
    expect(result.filename.endsWith('.svg')).toBe(true);
    expect(result.operation?.body.toString('utf8')).toBe('<svg>ok</svg>');
  });

  it('should resolve mime type from extension', () => {
    expect(getMimeTypeFromImageExtension('.png')).toBe('image/png');
    expect(getMimeTypeFromImageExtension('.unknown')).toBeUndefined();
  });
});

