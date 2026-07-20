/**
 * Tests for getSmtpConfiguration when ALLOW_EMAIL_REWRITE is false
 * (i.e. forced_sender_email is set in the JSON config).
 * This requires a separate module mock from the main test file.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as Cache from '../../../../src/database/cache';
import * as Conf from '../../../../src/config/conf';
import { getSmtpConfiguration } from '../../../../src/modules/smtpConfiguration/smtpConfiguration-domain';
import { SYSTEM_USER } from '../../../../src/utils/access';

const MOCK_JSON_CONFIG = {
  smtp_enabled: true,
  use_db_config: false,
  forced_sender_email: true,
  sender_email_address: 'noreply@example.com',
  hostname: 'smtp.example.com',
  port: 587,
  use_ssl: false,
  reject_unauthorized: false,
  auth_type: null,
  username: null,
  oauth_user: null,
  oauth_client_id: null,
  oauth_issuer: null,
  oauth_refresh_token_expires_at: null,
};

vi.mock('../../../../src/database/smtp', () => ({
  smtpTest: vi.fn(async () => true),
  ALLOW_EMAIL_REWRITE: false,
  SMTP_JSON_CONFIG: {
    smtp_enabled: true,
    use_db_config: false,
    forced_sender_email: true,
    sender_email_address: 'noreply@example.com',
    hostname: 'smtp.example.com',
    port: 587,
    use_ssl: false,
    reject_unauthorized: false,
    auth_type: null,
    username: null,
    oauth_user: null,
    oauth_client_id: null,
    oauth_issuer: null,
    oauth_refresh_token_expires_at: null,
  },
}));

vi.mock('../../../../src/modules/smtpConfiguration/smtpConfiguration-crypto', () => ({
  encryptSmtpSecret: vi.fn(async (v: string | null | undefined) => (v ? `encrypted:${v}` : v)),
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
}));

vi.mock('../../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/redis', () => ({
  notify: vi.fn().mockImplementation((_, element) => Promise.resolve(element)),
}));

vi.mock('../../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual('../../../../src/config/conf');
  return {
    ...actual,
    BUS_TOPICS: {
      Settings: {
        EDIT_TOPIC: 'SETTINGS_EDIT_TOPIC',
      },
    },
    isFeatureEnabled: vi.fn(() => true),
  };
});

const mockContext = { source: 'testing' } as any;
const mockUser = SYSTEM_USER;

const MOCK_SETTINGS_WITH_STORED = {
  id: 'settings-id-123',
  entity_type: 'Settings',
  smtp_configuration: { smtp_enabled: false, use_db_config: true, hostname: 'db.example.com', port: 587 },
} as any;

const MOCK_SETTINGS_WITHOUT_STORED = {
  id: 'settings-id-123',
  entity_type: 'Settings',
} as any;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(Conf.isFeatureEnabled).mockReturnValue(true);
});

describe('getSmtpConfiguration (forced mode — ALLOW_EMAIL_REWRITE=false)', () => {
  it('should return SMTP_JSON_CONFIG merged over stored config when forced', async () => {
    vi.mocked(Cache.getEntityFromCache).mockResolvedValue(MOCK_SETTINGS_WITH_STORED);
    const result = await getSmtpConfiguration(mockContext, mockUser);
    // JSON config fields must take precedence
    expect(result).toMatchObject(MOCK_JSON_CONFIG);
    expect(result?.forced_sender_email).toBe(true);
  });

  it('should return SMTP_JSON_CONFIG even when no stored config exists', async () => {
    vi.mocked(Cache.getEntityFromCache).mockResolvedValue(MOCK_SETTINGS_WITHOUT_STORED);
    const result = await getSmtpConfiguration(mockContext, mockUser);
    expect(result).toMatchObject(MOCK_JSON_CONFIG);
    expect(result?.forced_sender_email).toBe(true);
  });
});
