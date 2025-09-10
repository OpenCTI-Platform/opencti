import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';
import * as cache from '../../../src/database/cache';
import { checkXTMHubConnectivity } from '../../../src/domain/xtm-hub';
import { testContext } from '../../utils/testQuery';
import { HUB_REGISTRATION_MANAGER_USER } from '../../../src/utils/access';
import { XtmHubRegistrationStatus } from '../../../src/generated/graphql';
import { xtmHubClient } from '../../../src/modules/xtm/hub/xtm-hub-client';
import type { BasicStoreSettings } from '../../../src/types/settings';
import * as middleware from '../../../src/database/middleware';
import { ENTITY_TYPE_SETTINGS } from '../../../src/schema/internalObject';
import * as settingsModule from '../../../src/domain/settings';
import * as redisModule from '../../../src/database/redis';
import * as xtmHubEmail from '../../../src/modules/xtm/hub/xtm-hub-email';

describe('XTM hub', () => {
  describe('checkXTMHubConnectivity', () => {
    const xtm_hub_token = 'fake-token';
    let getEntityFromCacheSpy: MockInstance;
    let xtmHubClientSpy: MockInstance;
    let updateAttributeSpy: MockInstance;
    let sendAdministratorsLostConnectivityEmailSpy: MockInstance;

    beforeEach(() => {
      getEntityFromCacheSpy = vi.spyOn(cache, 'getEntityFromCache');
      xtmHubClientSpy = vi.spyOn(xtmHubClient, 'refreshRegistrationStatus');
      updateAttributeSpy = vi.spyOn(middleware, 'updateAttribute').mockResolvedValue({});
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

    it('should update registration status when connectivity is lost', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.Registered
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientSpy.mockResolvedValue('inactive');

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
      xtmHubClientSpy.mockResolvedValue('active');

      const result = await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(result.status).toBe(XtmHubRegistrationStatus.Registered);
      expect(updateAttributeSpy).toBeCalledWith(
        testContext,
        HUB_REGISTRATION_MANAGER_USER,
        'id',
        ENTITY_TYPE_SETTINGS,
        [
          { key: 'xtm_hub_registration_status', value: [XtmHubRegistrationStatus.Registered] },
          { key: 'xtm_hub_last_connectivity_check', value: [expect.any(Date)] },
          { key: 'xtm_hub_should_send_connectivity_email', value: [true] }
        ]
      );
    });

    it('should not update registration status when connectivity stays inactive', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.LostConnectivity
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientSpy.mockResolvedValue('inactive');

      const result = await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

      expect(result.status).toBe(XtmHubRegistrationStatus.LostConnectivity);
      expect(updateAttributeSpy).not.toBeCalled();
    });

    it('should only update last connectivity check when connection stays active', async () => {
      const settings: Partial<BasicStoreSettings> = {
        id: 'id',
        xtm_hub_token,
        xtm_hub_registration_status: XtmHubRegistrationStatus.Registered,
        xtm_hub_should_send_connectivity_email: true
      };
      getEntityFromCacheSpy.mockResolvedValue(settings);
      xtmHubClientSpy.mockResolvedValue('active');

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
        xtmHubClientSpy.mockResolvedValue('inactive');

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
        xtmHubClientSpy.mockResolvedValue('inactive');

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
        xtmHubClientSpy.mockResolvedValue('inactive');

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
        xtmHubClientSpy.mockResolvedValue('active');

        await checkXTMHubConnectivity(testContext, HUB_REGISTRATION_MANAGER_USER);

        expect(sendAdministratorsLostConnectivityEmailSpy).not.toBeCalled();
      });
    });
  });
});
