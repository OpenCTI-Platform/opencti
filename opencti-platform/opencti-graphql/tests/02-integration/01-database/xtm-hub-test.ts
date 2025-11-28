import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';
import * as cache from '../../../src/database/cache';
import * as confModule from '../../../src/config/conf';
import { autoRegisterOpenCTI, checkXTMHubConnectivity } from '../../../src/domain/xtm-hub';
import { testContext } from '../../utils/testQuery';
import { HUB_REGISTRATION_MANAGER_USER } from '../../../src/utils/access';
import { type AutoRegisterInput, XtmHubRegistrationStatus } from '../../../src/generated/graphql';
import { xtmHubClient } from '../../../src/modules/xtm/hub/xtm-hub-client';
import type { BasicStoreSettings } from '../../../src/types/settings';
import * as middleware from '../../../src/database/middleware';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import * as settingsModule from '../../../src/domain/settings';
import * as redisModule from '../../../src/database/redis';
import * as xtmHubEmail from '../../../src/modules/xtm/hub/xtm-hub-email';
import * as licensingModule from '../../../src/modules/settings/licensing';
import * as conf from '../../../src/config/conf';

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
        id: 'id'
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);

      await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [
          { key: 'xtm_hub_backend_is_reachable', value: [true] }
        ]
      );
    });

    it('should reset registration when platform is not found', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.Registered
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
          { key: 'xtm_hub_last_connectivity_check', value: [] }
        ]
      );
    });

    it('should update registration status when connectivity is lost', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.Registered
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
        [{ key: 'xtm_hub_registration_status', value: [XtmHubRegistrationStatus.LostConnectivity] }]
      );
    });

    it('should update registration status when connectivity is back up again', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
        xtm_hub_should_send_connectivity_email: false
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
          { key: 'xtm_hub_last_connectivity_check', value: [expect.any(Date)] }
        ]
      );
    });

    it('should update is backend reachable to false when xtm hub backend is not reachable', async () => {
      xtmHubClientIsBackendReachableSpy.mockResolvedValue({ isReachable: false });
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientRefreshStatusSpy.mockResolvedValue('inactive');

      await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [{ key: 'xtm_hub_backend_is_reachable', value: [false] }]
      );
    });

    it('should not update registration status when connectivity stays inactive', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity
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
        [{ key: 'xtm_hub_backend_is_reachable', value: [true] }]
      );
    });

    it('should only update last connectivity check when connection stays active', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.Registered,
        xtm_hub_should_send_connectivity_email: true
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
        [{ key: 'xtm_hub_last_connectivity_check', value: [expect.any(Date)] }]
      );
    });

    describe('lost connectivity email send', () => {
      it('should send connectivity email when 24 hours passed and connectivity is lost', async () => {
        const settings: Partial<BasicStoreSettings> = {
          id: 'id',
          xtm_hub_token,
          xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
          xtm_hub_last_connectivity_check: new Date(new Date().getTime() - 1000 * 60 * 60 * 24),
          xtm_hub_should_send_connectivity_email: true
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
          [{ key: 'xtm_hub_should_send_connectivity_email', value: [false] }]
        );
      });

      it('should not send connectivity email when connectivity is lost and 24 hours did not pass', async () => {
        const settings: Partial<BasicStoreSettings> = {
          id: 'id',
          xtm_hub_token,
          xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity,
          xtm_hub_last_connectivity_check: new Date(new Date().getTime() - 1000 * 60 * 60 * 23),
          xtm_hub_should_send_connectivity_email: true
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
          xtm_hub_should_send_connectivity_email: false
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
          xtm_hub_registration_status: XtmHubRegistrationStatus.Registered
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
    let confGetSpy: MockInstance;
    let getEntityFromCacheSpy: MockInstance;
    let getEnterpriseEditionInfoFromPemSpy: MockInstance;
    beforeEach(() => {
      autoRegisterSpy = vi.spyOn(xtmHubClient, 'autoRegister');
      settingsEditFieldSpy = vi.spyOn(settingsModule, 'settingsEditField');
      getEntityFromCacheSpy = vi.spyOn(cache, 'getEntityFromCache');
      confGetSpy = vi.spyOn(confModule.default, 'get');
      getEnterpriseEditionInfoFromPemSpy = vi.spyOn(licensingModule, 'getEnterpriseEditionInfoFromPem');
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should successfully auto-register a platform', async () => {
      const input: AutoRegisterInput = {
        platform_token: 'test-token'
      };

      autoRegisterSpy.mockResolvedValue({
        success: true
      });

      settingsEditFieldSpy.mockResolvedValue({});
      confGetSpy.mockReturnValue('platform_id');
      getEntityFromCacheSpy.mockResolvedValue({
        id: 'settings_id'
      });
      getEnterpriseEditionInfoFromPemSpy.mockReturnValue({
        license_enterprise: '',
        license_by_configuration: '',
        license_validated: true,
        license_valid_cert: '',
        license_customer: '',
        license_expired: '',
        license_extra_expiration: '',
        license_extra_expiration_days: '',
        license_expiration_date: '',
        license_start_date: '',
        license_expiration_prevention: '',
        license_platform: '',
        license_type: 'trial',
        license_platform_match: '',
        license_creator: '',
        license_global: ''
      });

      await autoRegisterOpenCTI(testContext, HUB_REGISTRATION_MANAGER_USER, input);
      expect(settingsEditFieldSpy).toHaveBeenCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'settings_id',
        [
          { key: 'xtm_hub_token', value: ['test-token'] },
          { key: 'xtm_hub_registration_status', value: ['registered'] }
        ]
      );
    });

    it('should handle registration failure', async () => {
      const input: AutoRegisterInput = {
        platform_token: 'test-token'
      };
      autoRegisterSpy.mockResolvedValue({
        success: false
      });

      settingsEditFieldSpy.mockResolvedValue({});

      await autoRegisterOpenCTI(testContext, HUB_REGISTRATION_MANAGER_USER, input);
      expect(settingsEditFieldSpy).not.toHaveBeenCalled();
    });
  });
});
