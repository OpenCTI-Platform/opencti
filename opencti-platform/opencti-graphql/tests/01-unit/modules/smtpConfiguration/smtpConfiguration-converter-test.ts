import { describe, expect, it } from 'vitest';
import convertSmtpConfigurationToStix from '../../../../src/modules/smtpConfiguration/smtpConfiguration-converter';

const BASE_INSTANCE = {
  _index: 'opencti_internal_objects-000001',
  internal_id: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
  standard_id: 'x-opencti-smtp-configuration--aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
  x_opencti_stix_ids: [],
  created_at: '2025-01-01T00:00:00.000Z',
  updated_at: '2025-01-02T00:00:00.000Z',
  base_type: 'ENTITY' as const,
  parent_types: ['Basic-Object', 'Internal-Object'],
  entity_type: 'SmtpConfiguration',
  smtp_enabled: true,
  use_db_config: false,
  sender_email_address: 'no-reply@example.com',
  hostname: 'smtp.example.com',
  port: 587,
  use_ssl: true,
  reject_unauthorized: true,
  auth_type: 'basic',
  username: 'smtp-user',
  oauth_user: undefined,
  oauth_client_id: undefined,
  oauth_issuer: undefined,
  // Secrets — must NOT appear in STIX output
  password: 'secret',
  oauth_client_secret: 'oauth-secret',
  oauth_access_token: 'access-token',
  oauth_refresh_token: 'refresh-token',
} as any;

describe('convertSmtpConfigurationToStix', () => {
  it('should map all non-secret fields to the STIX object', () => {
    const result = convertSmtpConfigurationToStix(BASE_INSTANCE);
    expect(result.smtp_enabled).toBe(true);
    expect(result.use_db_config).toBe(false);
    expect(result.sender_email_address).toBe('no-reply@example.com');
    expect(result.hostname).toBe('smtp.example.com');
    expect(result.port).toBe(587);
    expect(result.use_ssl).toBe(true);
    expect(result.reject_unauthorized).toBe(true);
    expect(result.auth_type).toBe('basic');
    expect(result.username).toBe('smtp-user');
  });

  it('should not include secret fields in the STIX output', () => {
    const result = convertSmtpConfigurationToStix(BASE_INSTANCE) as any;
    expect(result).not.toHaveProperty('password');
    expect(result).not.toHaveProperty('oauth_client_secret');
    expect(result).not.toHaveProperty('oauth_access_token');
    expect(result).not.toHaveProperty('oauth_refresh_token');
  });

  it('should include the OCTI extension with extension_type new-sdo', () => {
    const result = convertSmtpConfigurationToStix(BASE_INSTANCE);
    const octiExt = Object.values(result.extensions)[0] as any;
    expect(octiExt.extension_type).toBe('new-sdo');
  });
});
