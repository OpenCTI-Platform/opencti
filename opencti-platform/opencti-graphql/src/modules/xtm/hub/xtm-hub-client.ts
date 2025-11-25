import { getHttpClient } from '../../../utils/http-client';
import conf, { logApp, PLATFORM_VERSION } from '../../../config/conf';
import type { Success } from '../../../generated/graphql';

type RegistrationStatus = 'active' | 'inactive';

const HUB_BACKEND_URL = conf.get('xtm:xtmhub_api_override_url') ?? conf.get('xtm:xtmhub_url');

export const xtmHubClient = {
  isBackendReachable: async (): Promise<{ isReachable: boolean }> => {
    try {
      const httpClient = getHttpClient({
        baseURL: HUB_BACKEND_URL,
        responseType: 'json',
      });

      const response = await httpClient.head('/health', { timeout: 5000 });
      return { isReachable: response.status >= 200 && response.status < 300 };
    } catch (_error) {
      return { isReachable: false };
    }
  },
  refreshRegistrationStatus: async ({ platformId, token, platformVersion }: {
    platformId: string,
    token: string,
    platformVersion: string
  }): Promise<RegistrationStatus> => {
    const query = `
      mutation RefreshPlatformRegistrationConnectivityStatus($input: RefreshPlatformRegistrationConnectivityStatusInput!) {
        refreshPlatformRegistrationConnectivityStatus(input: $input) {
          status
        }
      }
    `;

    const variables = {
      input: {
        platformId,
        token,
        platformVersion
      }
    };
    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      responseType: 'json'
    });

    try {
      const response = await httpClient.post('/graphql-api', { query, variables });
      return response.data.data.refreshPlatformRegistrationConnectivityStatus.status;
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return 'inactive';
    }
  },
  autoRegister: async (platform: { platformId: string, platformToken: string, platformUrl: string, platformTitle: string }, enterpriseLicense: string): Promise<Success> => {
    const query = `
       mutation AutoRegisterPlatform($platform: PlatformInput!) {
        autoRegisterPlatform(platform: $platform) {
          success
        }
      }
    `;

    const variables = {
      platform: {
        id: platform.platformId,
        url: platform.platformUrl,
        title: platform.platformTitle,
        contract: enterpriseLicense,
        version: PLATFORM_VERSION
      }
    };
    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      responseType: 'json',
      headers: {
        'Content-Type': 'application/json',
        'XTM-Hub-Platform-Token': platform.platformToken,
        'XTM-Hub-Platform-Id': platform.platformId
      },
    });

    try {
      const response = await httpClient.post('/graphql-api', { query, variables });
      const { data, errors } = response.data;
      if ((errors?.length ?? 0) > 0 || !data?.autoRegisterPlatform?.success) {
        logApp.warn('XTM sent an error', { reason: errors[0] });
        return { success: false };
      }
      return data?.autoRegisterPlatform;
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return { success: false };
    }
  }
};
