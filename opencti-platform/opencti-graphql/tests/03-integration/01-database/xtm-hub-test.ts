import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';
import * as cache from '../../../src/database/cache';
import { autoRegisterOpenCTI, checkXTMHubConnectivity, loadAndSaveLatestNewsFeed } from '../../../src/domain/xtm-hub';
import { testContext } from '../../utils/testQuery';
import { HUB_REGISTRATION_MANAGER_USER } from '../../../src/utils/access';
import { type AutoRegisterInput, XtmHubRegistrationStatus } from '../../../src/generated/graphql';
import { type ProvisionedNewsFeedItem, xtmHubClient } from '../../../src/modules/xtm/hub/xtm-hub-client';
import type { BasicStoreSettings } from '../../../src/types/settings';
import * as middleware from '../../../src/database/middleware';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import * as settingsModule from '../../../src/domain/settings';
import * as redisModule from '../../../src/database/redis';
import * as xtmHubEmail from '../../../src/modules/xtm/hub/xtm-hub-email';
import * as conf from '../../../src/config/conf';
import * as newsFeedDomain from '../../../src/modules/xtm/hub/news-feed/news-feed-domain';
import { NewsFeedItemType } from '../../../src/modules/xtm/hub/news-feed/news-feed-types';

describe('XTM hub', () => {
  describe('checkXTMHubConnectivity', () => {
    const xtm_hub_token = 'fake-token';
    let getEntityFromCacheSpy: MockInstance;
    let xtmHubClientRefreshStatusSpy: MockInstance;
    let xtmHubClientIsBackendReachableSpy: MockInstance;
    let updateAttributeSpy: MockInstance;
    let sendAdministratorsLostConnectivityEmailSpy: MockInstance;

    beforeEach(() => {
      getEntityFromCacheSpy = vi.spyOn(cache, 'getEntityFromCache');
      xtmHubClientRefreshStatusSpy = vi.spyOn(xtmHubClient, 'refreshRegistrationStatus');
      xtmHubClientIsBackendReachableSpy = vi.spyOn(xtmHubClient, 'isBackendReachable').mockResolvedValue({ isReachable: true });
      updateAttributeSpy = vi.spyOn(middleware, 'updateAttribute').mockResolvedValue({} as unknown as any);
      sendAdministratorsLostConnectivityEmailSpy = vi.spyOn(xtmHubEmail, 'sendAdministratorsLostConnectivityEmail').mockResolvedValue({} as any);
      vi.spyOn(settingsModule, 'getSettings').mockResolvedValue({} as any);
      vi.spyOn(redisModule, 'notify').mockResolvedValue({});
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should return the unregistered status when platform is not registered', async () => {
      const settings = {};
      getEntityFromCacheSpy.mockResolvedValue(settings);

      const result = await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(result.status).toBe(XtmHubRegistrationStatus.Unregistered);
    });

    it('should check if backend is reachable', async () => {
      const settings = {
        id: 'id',
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);

      await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [
          { key: 'xtm_hub_backend_is_reachable', value: [true] },
        ],
      );
    });

    it('should reset registration when platform is not found', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.Registered,
      };

      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientRefreshStatusSpy.mockResolvedValue('not_found');

      const result = await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(result.status).toBe(XtmHubRegistrationStatus.Unregistered);
      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [
          { key: 'xtm_hub_token', value: [] },
          { key: 'xtm_hub_registration_status', value: [XtmHubRegistrationStatus.Unregistered] },
          { key: 'xtm_hub_registration_user_id', value: [] },
          { key: 'xtm_hub_registration_user_name', value: [] },
          { key: 'xtm_hub_registration_date', value: [] },
          { key: 'xtm_hub_last_connectivity_check', value: [] },
        ],
      );
    });

    it('should update registration status when connectivity is lost', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.Registered,
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientRefreshStatusSpy.mockResolvedValue('inactive');

      const result = await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(result.status).toBe(XtmHubRegistrationStatus.LostConnectivity);
      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [{ key: 'xtm_hub_registration_status', value: [XtmHubRegistrationStatus.LostConnectivity] }],
      );
    });

    it('should update registration status when connectivity is back up again', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
        xtm_hub_should_send_connectivity_email: false,
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientRefreshStatusSpy.mockResolvedValue('active');

      const result = await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(result.status).toBe(XtmHubRegistrationStatus.Registered);
      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [
          { key: 'xtm_hub_registration_status', value: [XtmHubRegistrationStatus.Registered] },
          { key: 'xtm_hub_should_send_connectivity_email', value: [true] },
          { key: 'xtm_hub_last_connectivity_check', value: [expect.any(Date)] },
        ],
      );
    });

    it('should update is backend reachable to false when xtm hub backend is not reachable', async () => {
      xtmHubClientIsBackendReachableSpy.mockResolvedValue({ isReachable: false });
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientRefreshStatusSpy.mockResolvedValue('inactive');

      await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [{ key: 'xtm_hub_backend_is_reachable', value: [false] }],
      );
    });

    it('should not update registration status when connectivity stays inactive', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientRefreshStatusSpy.mockResolvedValue('inactive');

      const result = await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(result.status).toBe(XtmHubRegistrationStatus.LostConnectivity);
      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [{ key: 'xtm_hub_backend_is_reachable', value: [true] }],
      );
    });

    it('should only update last connectivity check when connection stays active', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.Registered,
        xtm_hub_should_send_connectivity_email: true,
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientRefreshStatusSpy.mockResolvedValue('active');

      const result = await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(result.status).toBe(XtmHubRegistrationStatus.Registered);
      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [{ key: 'xtm_hub_last_connectivity_check', value: [expect.any(Date)] }],
      );
    });

    describe('lost connectivity email send', () => {
      it('should send connectivity email when 24 hours passed and connectivity is lost', async () => {
        const settings: Partial<BasicStoreSettings> = {
          id: 'id',
          xtm_hub_token,
          xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
          xtm_hub_last_connectivity_check: new Date(new Date().getTime() - 1000 * 60 * 60 * 24),
          xtm_hub_should_send_connectivity_email: true,
        };
        getEntityFromCacheSpy.mockResolvedValue(settings);
        xtmHubClientRefreshStatusSpy.mockResolvedValue('inactive');

        await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

        expect(sendAdministratorsLostConnectivityEmailSpy).toBeCalled();
        expect(updateAttributeSpy).toBeCalledWith(
          testContext,
          HUB_REGISTRATION_MANAGER_USER,
          'id',
          ENTITY_TYPE_SETTINGS,
          [{ key: 'xtm_hub_should_send_connectivity_email', value: [false] }],
        );
      });

      it('should not send connectivity email when connectivity is lost and 24 hours did not pass', async () => {
        const settings: Partial<BasicStoreSettings> = {
          id: 'id',
          xtm_hub_token,
          xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
          xtm_hub_last_connectivity_check: new Date(new Date().getTime() - 1000 * 60 * 60 * 23),
          xtm_hub_should_send_connectivity_email: true,
        };
        getEntityFromCacheSpy.mockResolvedValue(settings);
        xtmHubClientRefreshStatusSpy.mockResolvedValue('inactive');

        await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

        expect(sendAdministratorsLostConnectivityEmailSpy).not.toBeCalled();
      });

      it('should not send connectivity email when email was already sent', async () => {
        const settings: Partial<BasicStoreSettings> = {
          id: 'id',
          xtm_hub_token,
          xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
          xtm_hub_last_connectivity_check: new Date(new Date().getTime() - 1000 * 60 * 60 * 24),
          xtm_hub_should_send_connectivity_email: false,
        };
        getEntityFromCacheSpy.mockResolvedValue(settings);
        xtmHubClientRefreshStatusSpy.mockResolvedValue('inactive');

        await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

        expect(sendAdministratorsLostConnectivityEmailSpy).not.toBeCalled();
      });

      it('should not send connectivity email when connectivity is active', async () => {
        const settings: Partial<BasicStoreSettings> = {
          id: 'id',
          xtm_hub_token,
          xtm_hub_registration_status: XtmHubRegistrationStatus.Registered,
        };
        getEntityFromCacheSpy.mockResolvedValue(settings);
        xtmHubClientRefreshStatusSpy.mockResolvedValue('active');

        await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

        expect(sendAdministratorsLostConnectivityEmailSpy).not.toBeCalled();
      });

      it('should not send connectivity email when email sending is disabled via configuration', async () => {
        const settings: Partial<BasicStoreSettings> = {
          id: 'id',
          xtm_hub_token,
          xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
          xtm_hub_last_connectivity_check: new Date(new Date().getTime() - 1000 * 60 * 60 * 24),
          xtm_hub_should_send_connectivity_email: true,
        };
        getEntityFromCacheSpy.mockResolvedValue(settings);
        xtmHubClientRefreshStatusSpy.mockResolvedValue('inactive');
        vi.spyOn(conf, 'booleanConf').mockReturnValue(false);

        await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

        expect(sendAdministratorsLostConnectivityEmailSpy).not.toBeCalled();
      });
    });
  });

  describe('autoRegisterOpenCTI', () => {
    let autoRegisterSpy: MockInstance;
    let settingsEditFieldSpy: MockInstance;
    let getEntityFromCacheSpy: MockInstance;
    let getEntitiesListFromCacheSpy: MockInstance;
    beforeEach(() => {
      autoRegisterSpy = vi.spyOn(xtmHubClient, 'autoRegister');
      settingsEditFieldSpy = vi.spyOn(settingsModule, 'settingsEditField');
      getEntityFromCacheSpy = vi.spyOn(cache, 'getEntityFromCache');
      getEntitiesListFromCacheSpy = vi.spyOn(cache, 'getEntitiesListFromCache');
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should successfully auto-register a platform', async () => {
      const input: AutoRegisterInput = {
        platform_token: 'test-token',
      };

      autoRegisterSpy.mockResolvedValue({
        success: true,
      });

      settingsEditFieldSpy.mockResolvedValue({});
      getEntityFromCacheSpy.mockResolvedValue({
        id: 'settings_id',
      });
      getEntitiesListFromCacheSpy.mockResolvedValue([
        { user_service_account: false },
        { user_service_account: true },
        { user_service_account: false },
      ]);

      await autoRegisterOpenCTI(testContext, HUB_REGISTRATION_MANAGER_USER, input);
      expect(autoRegisterSpy).toHaveBeenCalledWith(
        {
          platformId: 'settings_id',
          platformToken: 'test-token',
          platformUrl: undefined,
          platformTitle: '',
        },
        expect.any(String),
        2,
      );
      expect(settingsEditFieldSpy).toHaveBeenCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'settings_id',
        [
          { key: 'xtm_hub_token', value: ['test-token'] },
          { key: 'xtm_hub_registration_status', value: ['registered'] },
        ],
      );
    });

    it('should handle registration failure', async () => {
      const input: AutoRegisterInput = {
        platform_token: 'test-token',
      };
      autoRegisterSpy.mockResolvedValue({
        success: false,
      });

      settingsEditFieldSpy.mockResolvedValue({});
      getEntityFromCacheSpy.mockResolvedValue({
        id: 'settings_id',
      });
      getEntitiesListFromCacheSpy.mockResolvedValue([
        { user_service_account: false },
      ]);

      await autoRegisterOpenCTI(testContext, HUB_REGISTRATION_MANAGER_USER, input);
      expect(settingsEditFieldSpy).not.toHaveBeenCalled();
    });
  });

  describe('loadAndSaveLatestNewsFeed', () => {
    let getEntityFromCacheSpy: MockInstance;
    let consumeProvisionedNewsFeedItemsSpy: MockInstance;
    let addNewsFeedSpy: MockInstance;
    let updateAttributeSpy: MockInstance;
    let booleanConfSpy: MockInstance;

    const mockSettings = {
      id: 'settings_id',
      xtm_hub_token: 'fake-token',
    } as unknown as BasicStoreSettings;

    const mockUsers = [
      { id: 'user-1', user_service_account: false },
      { id: 'user-2', user_service_account: false },
    ] as any[];

    const mockNewsFeedItems: ProvisionedNewsFeedItem[] = [
      { title: 'News 1', type: NewsFeedItemType.RESOURCE_CUSTOM_DASHBOARD, tags: [], metadata: [], creation_date: new Date('2026-01-01') },
      { title: 'News 2', type: NewsFeedItemType.RESOURCE_CUSTOM_DASHBOARD, tags: [], metadata: [], creation_date: new Date('2026-01-02') },
    ];

    beforeEach(() => {
      getEntityFromCacheSpy = vi.spyOn(cache, 'getEntityFromCache').mockResolvedValue(mockSettings as any);
      vi.spyOn(cache, 'getEntitiesListFromCache').mockResolvedValue(mockUsers as any);
      consumeProvisionedNewsFeedItemsSpy = vi.spyOn(xtmHubClient, 'consumeProvisionedNewsFeedItems').mockResolvedValue({
        news_feed_items: mockNewsFeedItems,
        available_news_feed_types: ['type-1'],
      } as any);
      addNewsFeedSpy = vi.spyOn(newsFeedDomain, 'addNewsFeed').mockResolvedValue({} as any);
      updateAttributeSpy = vi.spyOn(middleware, 'updateAttribute').mockResolvedValue({} as unknown as any);
      booleanConfSpy = vi.spyOn(conf, 'booleanConf').mockReturnValue(true);
      vi.spyOn(settingsModule, 'getSettings').mockResolvedValue({} as any);
      vi.spyOn(redisModule, 'notify').mockResolvedValue({});
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should do nothing when news feed feature is disabled', async () => {
      booleanConfSpy.mockReturnValue(false);

      await loadAndSaveLatestNewsFeed(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(getEntityFromCacheSpy).not.toBeCalled();
      expect(consumeProvisionedNewsFeedItemsSpy).not.toBeCalled();
    });

    it('should do nothing when platform is not registered (no token)', async () => {
      getEntityFromCacheSpy.mockResolvedValue({ id: 'settings_id' } as any);

      await loadAndSaveLatestNewsFeed(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(consumeProvisionedNewsFeedItemsSpy).not.toBeCalled();
      expect(addNewsFeedSpy).not.toBeCalled();
    });

    it('should update xtm_hub_available_news_feed_types in settings even when there are no news feed items', async () => {
      consumeProvisionedNewsFeedItemsSpy.mockResolvedValue({
        news_feed_items: [],
        available_news_feed_types: ['type-1', 'type-2'],
      });

      await loadAndSaveLatestNewsFeed(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(addNewsFeedSpy).not.toBeCalled();
      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'settings_id',
        ENTITY_TYPE_SETTINGS,
        [{ key: 'xtm_hub_available_news_feed_types', value: ['type-1', 'type-2'] }],
      );
    });

    it('should call loadProvisionedNewsFeedItems with correct platform credentials', async () => {
      await loadAndSaveLatestNewsFeed(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(consumeProvisionedNewsFeedItemsSpy).toBeCalledWith('settings_id', 'fake-token');
    });

    it('should add each news feed item for each user', async () => {
      await loadAndSaveLatestNewsFeed(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(addNewsFeedSpy).toBeCalledTimes(mockNewsFeedItems.length * mockUsers.length);
      for (const feedItem of mockNewsFeedItems) {
        for (const user of mockUsers) {
          expect(addNewsFeedSpy).toBeCalledWith(
            testContext,
            user,
            { ...feedItem, news_feed_type: feedItem.type, user_id: (user as any).id },
          );
        }
      }
    });

    it('should update xtm_hub_available_news_feed_types in settings after processing', async () => {
      await loadAndSaveLatestNewsFeed(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'settings_id',
        ENTITY_TYPE_SETTINGS,
        [{ key: 'xtm_hub_available_news_feed_types', value: ['type-1'] }],
      );
    });

    it('should continue processing other items when adding a news feed item fails for one user', async () => {
      addNewsFeedSpy
        .mockRejectedValueOnce(new Error('Add news feed failed'))
        .mockResolvedValue({} as any);

      await loadAndSaveLatestNewsFeed(testContext, HUB_REGISTRATION_MANAGER_USER);

      // All combinations should still be attempted despite one failure
      expect(addNewsFeedSpy).toBeCalledTimes(mockNewsFeedItems.length * mockUsers.length);
      // Settings should still be updated
      expect(updateAttributeSpy).toBeCalled();
    });
  });
});
