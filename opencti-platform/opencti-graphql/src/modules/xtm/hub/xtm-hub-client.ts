import { getHttpClient } from '../../../utils/http-client';
import conf, { logApp } from '../../../config/conf';

type RegistrationStatus = 'active' | 'inactive';

const HUB_BACKEND_URL = conf.get('xtm:xtmhub_api_override_url') ?? conf.get('xtm:xtmhub_url');

export const xtmHubClient = {
  refreshRegistrationStatus: async ({ platformId, token, platformVersion }: { platformId: string, token: string, platformVersion: string }): Promise<RegistrationStatus> => {
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
  }
};
