import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mocks (must be declared before imports) ─────────────────────────────

vi.mock('../../../../src/modules/xtm/one/xtm-one-client', () => ({
  default: {
    isConfigured: vi.fn(),
    register: vi.fn(),
  },
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
}));

vi.mock('../../../../src/modules/settings/licensing', () => ({
  getEnterpriseEditionActivePem: vi.fn(),
  decodeLicensePem: vi.fn(),
}));

vi.mock('../../../../src/config/conf', () => ({
  default: { get: vi.fn() },
  logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  PLATFORM_VERSION: '6.0.0-test',
}));

// ── Imports (after mocks) ───────────────────────────────────────────────

import xtmOneClient from '../../../../src/modules/xtm/one/xtm-one-client';
import { getEntityFromCache } from '../../../../src/database/cache';
import { getEnterpriseEditionActivePem, decodeLicensePem } from '../../../../src/modules/settings/licensing';
import { registerWithXtmOne } from '../../../../src/modules/xtm/one/xtm-one';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

// ── Test fixtures ───────────────────────────────────────────────────────

const mockContext = {} as AuthContext;
const mockUser = { id: 'user-1' } as AuthUser;

const mockSettings = {
  id: 'settings-id-123',
  internal_id: 'settings-internal-id-123',
  platform_url: 'https://opencti.test',
  platform_title: 'Test OpenCTI',
  enterprise_license: 'some-pem',
};

const mockRegistrationResponse = {
  status: 'ok',
  platform_identifier: 'opencti',
  ee_enabled: true,
  user_integrations: 0,
  chat_web_token: null,
  intent_catalog: [
    {
      intent: 'global.assistant',
      description: 'General-purpose assistant',
      agents: [
        {
          agent_id: 'agent-1',
          agent_name: 'TestAgent',
          agent_slug: 'test-agent',
          agent_description: null,
          vertical: 'cti',
          priority: 1,
          is_default: true,
          is_locked: false,
          enabled: true,
        },
      ],
    },
  ],
};

// ── Tests ───────────────────────────────────────────────────────────────

describe('registerWithXtmOne', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should do nothing when xtmOneClient is not configured', async () => {
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(false);

    await registerWithXtmOne(mockContext, mockUser);

    expect(xtmOneClient.register).not.toHaveBeenCalled();
    expect(getEntityFromCache).not.toHaveBeenCalled();
  });

  it('should warn and return when settings are not available', async () => {
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue(undefined as any);

    await registerWithXtmOne(mockContext, mockUser);

    expect(xtmOneClient.register).not.toHaveBeenCalled();
  });

  it('should call register with correct payload when configured', async () => {
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue(mockSettings as any);
    vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: 'test-pem', licenseByConfiguration: false });
    vi.mocked(decodeLicensePem).mockReturnValue({ license_validated: true, license_type: 'enterprise' } as any);
    vi.mocked(xtmOneClient.register).mockResolvedValue(mockRegistrationResponse);

    await registerWithXtmOne(mockContext, mockUser);

    expect(xtmOneClient.register).toHaveBeenCalledTimes(1);
    const callArgs = vi.mocked(xtmOneClient.register).mock.calls[0][0];
    expect(callArgs.platform_identifier).toBe('opencti');
    expect(callArgs.platform_url).toBe('https://opencti.test');
    expect(callArgs.platform_title).toBe('Test OpenCTI');
    expect(callArgs.platform_id).toBe('settings-internal-id-123');
    expect(callArgs.enterprise_license_pem).toBe('test-pem');
    expect(callArgs.license_type).toBe('enterprise');
    expect(callArgs.business_vertical).toBe('cti');
    expect(callArgs.intents.length).toBeGreaterThan(0);
    expect(callArgs.intents.map((i: { name: string }) => i.name)).toContain('global.assistant');
  });

  it('should update discoveredIntentCatalog on successful registration', async () => {
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue(mockSettings as any);
    vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: 'test-pem', licenseByConfiguration: false });
    vi.mocked(decodeLicensePem).mockReturnValue({ license_validated: true, license_type: 'enterprise' } as any);
    vi.mocked(xtmOneClient.register).mockResolvedValue(mockRegistrationResponse);

    await registerWithXtmOne(mockContext, mockUser);

    // Import the getter to check the catalog was updated
    const { getDiscoveredIntentCatalog } = await import('../../../../src/modules/xtm/one/xtm-one');
    const catalog = getDiscoveredIntentCatalog();
    expect(catalog).toEqual(mockRegistrationResponse.intent_catalog);
    expect(catalog[0].agents.length).toBe(1);
    expect(catalog[0].agents[0].agent_name).toBe('TestAgent');
  });

  it('should handle null register response gracefully', async () => {
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue(mockSettings as any);
    vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: undefined, licenseByConfiguration: false });
    vi.mocked(decodeLicensePem).mockImplementation(() => {
      throw new Error('invalid PEM');
    });
    vi.mocked(xtmOneClient.register).mockResolvedValue(null);

    // Should not throw
    await registerWithXtmOne(mockContext, mockUser);

    expect(xtmOneClient.register).toHaveBeenCalledTimes(1);
    const callArgs = vi.mocked(xtmOneClient.register).mock.calls[0][0];
    expect(callArgs.enterprise_license_pem).toBeUndefined();
    expect(callArgs.license_type).toBeUndefined();
  });

  it('should send license_type undefined when decodeLicensePem throws', async () => {
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue(mockSettings as any);
    vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: 'bad-pem', licenseByConfiguration: false });
    vi.mocked(decodeLicensePem).mockImplementation(() => {
      throw new Error('bad cert');
    });
    vi.mocked(xtmOneClient.register).mockResolvedValue(mockRegistrationResponse);

    await registerWithXtmOne(mockContext, mockUser);

    const callArgs = vi.mocked(xtmOneClient.register).mock.calls[0][0];
    expect(callArgs.license_type).toBeUndefined();
  });

  it('should send license_type undefined when license is not validated', async () => {
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue(mockSettings as any);
    vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: 'pem', licenseByConfiguration: false });
    vi.mocked(decodeLicensePem).mockReturnValue({ license_validated: false, license_type: 'enterprise' } as any);
    vi.mocked(xtmOneClient.register).mockResolvedValue(mockRegistrationResponse);

    await registerWithXtmOne(mockContext, mockUser);

    const callArgs = vi.mocked(xtmOneClient.register).mock.calls[0][0];
    expect(callArgs.license_type).toBeUndefined();
  });

  it('should fallback platform_id to settings.id when internal_id is missing', async () => {
    const settingsNoInternalId = { ...mockSettings, internal_id: undefined };
    vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
    vi.mocked(getEntityFromCache).mockResolvedValue(settingsNoInternalId as any);
    vi.mocked(getEnterpriseEditionActivePem).mockReturnValue({ pem: undefined, licenseByConfiguration: false });
    vi.mocked(decodeLicensePem).mockImplementation(() => {
      throw new Error('no pem');
    });
    vi.mocked(xtmOneClient.register).mockResolvedValue(mockRegistrationResponse);

    await registerWithXtmOne(mockContext, mockUser);

    const callArgs = vi.mocked(xtmOneClient.register).mock.calls[0][0];
    expect(callArgs.platform_id).toBe('settings-id-123');
  });
});
