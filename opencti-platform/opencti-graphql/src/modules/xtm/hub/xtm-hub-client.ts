import { getHttpClient, getResponseError } from '../../../utils/http-client';
import conf, { logApp, PLATFORM_VERSION } from '../../../config/conf';
import type { Success } from '../../../generated/graphql';
import { type NewsFeedItemMetadata, NewsFeedItemType } from './news-feed/news-feed-types';

type RegistrationStatus = 'active' | 'inactive' | 'not_found';
export type HubPlatformContract = 'CE' | 'EE';

interface HubGraphQLError {
  message?: string;
  extensions?: { code?: string };
}

interface RefreshRegistrationStatusResult {
  status?: RegistrationStatus;
  errors?: HubGraphQLError[];
}

// A hub older than the edition refresh rejects the unknown input field. GraphQL quotes the field name it rejects,
// while the input value it echoes back holds an unquoted `platformContract` key on any other input error.
const isPlatformContractRejected = (errors?: HubGraphQLError[]) => (errors ?? [])
  .some((error) => typeof error?.message === 'string' && error.message.includes('"platformContract"'));

// GraphQL input errors echo the submitted variables, the platform token included: never log their messages.
const hubErrorCodes = (errors?: HubGraphQLError[]) => (errors ?? [])
  .map((error) => error?.extensions?.code)
  .filter((code): code is string => typeof code === 'string');

let isPlatformContractFallbackLogged = false;

export interface ProvisionedNewsFeedItem {
  id: string;
  title: string;
  type: NewsFeedItemType;
  tags: string[];
  metadata: NewsFeedItemMetadata[];
  creation_date: Date;
  is_deleted: boolean;
}

interface ConsumeProvisionedNewsFeedItemsResponse {
  news_feed_items: ProvisionedNewsFeedItem[];
  available_news_feed_types: NewsFeedItemType[];
}

const HUB_BACKEND_URL = conf.get('xtm:xtmhub_api_override_url') ?? conf.get('xtm:xtmhub_url');
const HUB_OPENCTI_IDENTIFIER = 'opencti';

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
  refreshRegistrationStatus: async ({ platformId, token, platformVersion, platformContract }: {
    platformId: string;
    token: string;
    platformVersion: string;
    platformContract: HubPlatformContract;
  }): Promise<RegistrationStatus> => {
    const query = `
      mutation RefreshPlatformRegistrationConnectivityStatus($input: RefreshPlatformRegistrationConnectivityStatusInput!) {
        refreshPlatformRegistrationConnectivityStatus(input: $input) {
          status
        }
      }
    `;

    const input = {
      platformId,
      token,
      platformVersion,
      platformIdentifier: HUB_OPENCTI_IDENTIFIER,
    };
    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      responseType: 'json',
    });
    const refresh = async (variables: { input: Record<string, string> }): Promise<RefreshRegistrationStatusResult> => {
      try {
        const response = await httpClient.post('/graphql-api', { query, variables });
        return {
          status: response.data?.data?.refreshPlatformRegistrationConnectivityStatus?.status,
          errors: response.data?.errors,
        };
      } catch (error) {
        const errors = getResponseError(error)?.data?.errors;
        if (!errors) {
          throw error;
        }
        return { errors };
      }
    };

    try {
      let result = await refresh({ input: { ...input, platformContract } });
      if (!result.status && isPlatformContractRejected(result.errors)) {
        if (!isPlatformContractFallbackLogged) {
          logApp.warn('[XTMH] XTM Hub does not accept the platform edition yet, refreshing the connectivity without it');
          isPlatformContractFallbackLogged = true;
        }
        result = await refresh({ input });
      }
      if (!result.status) {
        logApp.warn('XTM Hub sent an error', { codes: hubErrorCodes(result.errors) });
        return 'inactive';
      }
      return result.status;
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return 'inactive';
    }
  },
  autoRegister: async (platform: { platformId: string; platformToken: string; platformUrl: string; platformTitle: string },
    enterpriseLicense: string,
    existing_users_count: number): Promise<Success> => {
    const query = `
       mutation AutoRegisterPlatform($input: AutoRegisterPlatformInput!) {
        autoRegisterPlatform(input: $input) {
          success
        }
      }
    `;

    const variables = {
      input: {
        platform: {
          id: platform.platformId,
          url: platform.platformUrl,
          title: platform.platformTitle,
          contract: enterpriseLicense,
          version: PLATFORM_VERSION,
        },
        existing_users_count,
      },
    };
    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      responseType: 'json',
      headers: {
        'Content-Type': 'application/json',
        'XTM-Hub-Platform-Token': platform.platformToken,
        'XTM-Hub-Platform-Id': platform.platformId,
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
  },
  consumeProvisionedNewsFeedItems: async (platformId: string, platformToken: string): Promise<ConsumeProvisionedNewsFeedItemsResponse> => {
    const mutation = `
      mutation ConsumeProvisionedNewsFeedItems {
        consumeProvisionedNewsFeedItems {
          news_feed_items {
            id
            title
            type
            tags
            metadata {
              key
              value
            }
            creation_date
            is_deleted
          }
          available_news_feed_types
        }
      }
    `;

    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      responseType: 'json',
      headers: {
        'Content-Type': 'application/json',
        'XTM-Hub-Platform-Id': platformId,
        'XTM-Hub-Platform-Token': platformToken,
      },
    });

    const emptyResponse: ConsumeProvisionedNewsFeedItemsResponse = { news_feed_items: [], available_news_feed_types: [] };

    try {
      const response = await httpClient.post('/graphql-api', { query: mutation });
      const { data, errors } = response.data;
      if ((errors?.length ?? 0) > 0) {
        logApp.warn('XTM Hub consumeProvisionedNewsFeedItems error', { reason: errors?.[0] });
        return emptyResponse;
      }
      return data?.consumeProvisionedNewsFeedItems ?? emptyResponse;
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return emptyResponse;
    }
  },
  contactUs: async (platform: { platformId: string; platformToken: string }, message: string): Promise<Success> => {
    const query = `
      mutation ContactUs($message: String) {
        contactUs(message: $message) {
          success
        }
      }
    `;

    const variables = {
      message,
    };

    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      responseType: 'json',
      headers: {
        'Content-Type': 'application/json',
        'XTM-Hub-Platform-Token': platform.platformToken,
        'XTM-Hub-Platform-Id': platform.platformId,
      },
    });

    try {
      const response = await httpClient.post('/graphql-api', { query, variables });
      const { data, errors } = response.data;
      if ((errors?.length ?? 0) > 0 || !data?.contactUs?.success) {
        logApp.warn('XTM Hub contactUs failed', { reason: errors?.[0] });
        return { success: false };
      }
      return data?.contactUs;
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return { success: false };
    }
  },
};
