import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreSettings } from '../../../src/types/settings';

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
  getEntitiesListFromCache: vi.fn(async () => []),
}));
vi.mock('../../../src/database/middleware', () => ({ updateAttribute: vi.fn() }));
vi.mock('../../../src/database/redis', () => ({ notify: vi.fn() }));
vi.mock('../../../src/domain/settings', () => ({ getSettings: vi.fn(), settingsEditField: vi.fn() }));
vi.mock('../../../src/modules/xtm/hub/xtm-hub-email', () => ({ sendAdministratorsLostConnectivityEmail: vi.fn() }));
vi.mock('../../../src/modules/settings/licensing', () => ({
  getEnterpriseEditionInfo: vi.fn(() => ({ license_validated: false, license_type: 'CE' })),
}));
vi.mock('../../../src/modules/xtm/hub/news-feed/news-feed-domain', () => ({
  deleteNewsFeedItemsByExternalId: vi.fn(),
  upsertNewsFeed: vi.fn(),
}));
vi.mock('../../../src/modules/xtm/hub/xtm-hub-client', () => ({
  xtmHubClient: {
    isBackendReachable: vi.fn(async () => ({ isReachable: true })),
    refreshRegistrationStatus: vi.fn(async () => ({ status: 'active', commercialModel: null, organizationName: null })),
    consumeProvisionedNewsFeedItems: vi.fn(async () => ({ news_feed_items: [], available_news_feed_types: [] })),
    contactUs: vi.fn(async () => ({ success: true })),
    autoRegister: vi.fn(async () => ({ success: true })),
  },
}));

const { getEntityFromCache } = await import('../../../src/database/cache');
const { updateAttribute } = await import('../../../src/database/middleware');
const { xtmHubClient } = await import('../../../src/modules/xtm/hub/xtm-hub-client');
const {
  autoRegisterOpenCTI,
  checkXTMHubConnectivity,
  contactUsXtmHub,
  getXtmHubCredentials,
  loadAndSaveLatestNewsFeed,
} = await import('../../../src/domain/xtm-hub');

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const PLATFORM_ID = 'platform-id';
const TOKEN = 'platform-token';
const ENROLLED_AT = new Date('2026-11-27T10:00:00.000Z');

const givenSettings = (settings: Partial<BasicStoreSettings>) => {
  vi.mocked(getEntityFromCache).mockResolvedValue({ id: PLATFORM_ID, internal_id: PLATFORM_ID, ...settings } as BasicStoreSettings);
};

describe('getXtmHubCredentials', () => {
  it.each([
    { registration: 'an enrolled platform', settings: { xtm_hub_key_enrolled_at: ENROLLED_AT }, credentials: { kind: 'key' } },
    {
      registration: 'an enrolled platform that still stores its token',
      settings: { xtm_hub_key_enrolled_at: ENROLLED_AT, xtm_hub_token: TOKEN },
      credentials: { kind: 'key' },
    },
    { registration: 'a platform registered with a token only', settings: { xtm_hub_token: TOKEN }, credentials: { kind: 'token', token: TOKEN } },
    { registration: 'a platform not registered', settings: {}, credentials: undefined },
    { registration: 'a platform with an empty token', settings: { xtm_hub_token: '' }, credentials: undefined },
  ])('should give $registration the credentials $credentials.kind', ({ settings, credentials }) => {
    expect(getXtmHubCredentials(settings)).toEqual(credentials);
  });
});

describe('XTM Hub calls of the platform', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const calls = [
    {
      name: 'the connectivity check',
      run: () => checkXTMHubConnectivity(context, user),
      sent: () => vi.mocked(xtmHubClient.refreshRegistrationStatus).mock.calls.map(([input]) => input.credentials),
    },
    {
      name: 'the news feed',
      run: () => loadAndSaveLatestNewsFeed(context, user),
      sent: () => vi.mocked(xtmHubClient.consumeProvisionedNewsFeedItems).mock.calls.map(([, credentials]) => credentials),
    },
    {
      name: 'contact us',
      run: () => contactUsXtmHub(context, user, 'Hello'),
      sent: () => vi.mocked(xtmHubClient.contactUs).mock.calls.map(([platform]) => platform.credentials),
    },
  ];

  it.each(calls)('$name should sign with the key once enrolled, even with a token still stored', async ({ run, sent }) => {
    // Given
    givenSettings({ xtm_hub_key_enrolled_at: ENROLLED_AT, xtm_hub_token: TOKEN });

    // When
    await run();

    // Then
    expect(sent()).toEqual([{ kind: 'key' }]);
  });

  it.each(calls)('$name should send the token before enrollment', async ({ run, sent }) => {
    // Given
    givenSettings({ xtm_hub_token: TOKEN });

    // When
    await run();

    // Then
    expect(sent()).toEqual([{ kind: 'token', token: TOKEN }]);
  });

  it.each(calls)('$name should not call XTM Hub when the platform is not registered', async ({ run, sent }) => {
    // Given
    givenSettings({});

    // When
    await run();

    // Then
    expect(sent()).toEqual([]);
  });

  it('auto-register should send the token it was given, and nothing without one', async () => {
    // Given
    givenSettings({ platform_url: 'http://opencti.test', platform_title: 'OpenCTI' });

    // When
    const withToken = await autoRegisterOpenCTI(context, user, { platform_token: TOKEN });
    const withoutToken = await autoRegisterOpenCTI(context, user, { platform_token: '' });

    // Then
    expect({
      withToken,
      withoutToken,
      sent: vi.mocked(xtmHubClient.autoRegister).mock.calls.map(([platform]) => platform.credentials),
    }).toEqual({
      withToken: { success: true },
      withoutToken: { success: false },
      sent: [{ kind: 'token', token: TOKEN }],
    });
  });

  it('should forget the key enrollment when XTM Hub no longer knows the registration', async () => {
    // Given
    givenSettings({ xtm_hub_key_enrolled_at: ENROLLED_AT });
    vi.mocked(xtmHubClient.refreshRegistrationStatus).mockResolvedValueOnce({ status: 'not_found', commercialModel: null, organizationName: null });

    // When
    await checkXTMHubConnectivity(context, user);

    // Then
    const resetKeys = vi.mocked(updateAttribute).mock.calls
      .flatMap(([, , , , updates]) => updates as { key: string; value: unknown[] }[])
      .filter(({ value }) => value.length === 0)
      .map(({ key }) => key);
    expect(resetKeys).toContain('xtm_hub_key_enrolled_at');
  });
});
