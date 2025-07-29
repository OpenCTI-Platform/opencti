import { getHttpClient } from './http-client';
import conf, { logApp } from '../config/conf';

type EnrollmentStatus = 'active' | 'inactive';

const HUB_BACKEND_URL = conf.get('xtm:xtmhub_backend_url');

export const hubClient = {
  loadEnrollmentStatus: async ({ platformId, token }: { platformId: string, token: string }): Promise<EnrollmentStatus> => {
    const query = `
      query OctiPlatformEnrollmentStatus($input: OCTIPlatformEnrollmentStatusInput!) {
        octiPlatformEnrollmentStatus(input: $input) {
          status
        }
      }
    `;

    const variables = {
      input: {
        platformId,
        token
      }
    };
    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      responseType: 'json'
    });

    try {
      const response = await httpClient.post('/graphql-api', { query, variables });
      return response.data.data.octiPlatformEnrollmentStatus.status;
    } catch (error) {
      logApp.warn(error);
      return 'inactive';
    }
  }
};
