import { getHttpClient, getResponseError } from '../../../utils/http-client';
import conf, { logApp, PLATFORM_VERSION } from '../../../config/conf';
import type { Success } from '../../../generated/graphql';
import { type NewsFeedItemMetadata, NewsFeedItemType } from './news-feed/news-feed-types';

type RegistrationStatus = 'active' | 'inactive' | 'not_found';
export type HubPlatformContract = 'CE' | 'EE';
export type HubCommercialModel = 'saas' | 'other';

export interface RefreshRegistrationStatusResult {
  status: RegistrationStatus;
  // Null when the hub does not return it (unreachable hub, error, unknown value).
  commercialModel: HubCommercialModel | null;
}

interface HubGraphQLError {
  message?: string;
  extensions?: { code?: string };
}

interface HubRefreshAnswer {
  status?: RegistrationStatus;
  commercialModel?: unknown;
  errors?: HubGraphQLError[];
}

const INACTIVE_REFRESH_RESULT: RefreshRegistrationStatusResult = { status: 'inactive', commercialModel: null };

// The input coercion error a hub older than the edition refresh (graphql-js 16) returns for the unknown field.
const PLATFORM_CONTRACT_UNKNOWN_FIELD = 'Field "platformContract" is not defined by type "RefreshPlatformRegistrationConnectivityStatusInput"';
// The validation error a hub older than the commercial model refresh (graphql-js 16) returns for the unknown selected field.
const COMMERCIAL_MODEL_UNKNOWN_FIELD = 'Cannot query field "commercialModel" on type';
const isFieldRejected = (errors: HubGraphQLError[] | undefined, fieldError: string) => (errors ?? [])
  .some((error) => typeof error?.message === 'string' && error.message.includes(fieldError));

// GraphQL input errors echo the submitted variables, the platform token included: never log their messages.
const hubErrorCodes = (errors?: HubGraphQLError[]) => (errors ?? [])
  .map((error) => error?.extensions?.code)
  .filter((code): code is string => typeof code === 'string');

let isPlatformContractFallbackLogged = false;
let isCommercialModelFallbackLogged = false;

// The hub answers with its own CommercialModel enum: a value this platform does not know yet is ignored rather than stored.
const toCommercialModel = (value: unknown): HubCommercialModel | null => {
  if (typeof value !== 'string') {
    return null;
  }
  const commercialModel = value.toLowerCase();
  return commercialModel === 'saas' || commercialModel === 'other' ? commercialModel : null;
};

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
  }): Promise<RefreshRegistrationStatusResult> => {
    const buildQuery = (withCommercialModel: boolean) => `
      mutation RefreshPlatformRegistrationConnectivityStatus($input: RefreshPlatformRegistrationConnectivityStatusInput!) {
        refreshPlatformRegistrationConnectivityStatus(input: $input) {
          status${withCommercialModel ? '\n          commercialModel' : ''}
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
    const refresh = async (withPlatformContract: boolean, withCommercialModel: boolean): Promise<HubRefreshAnswer> => {
      const variables = { input: withPlatformContract ? { ...input, platformContract } : input };
      try {
        const response = await httpClient.post('/graphql-api', { query: buildQuery(withCommercialModel), variables });
        const refreshed = response.data?.data?.refreshPlatformRegistrationConnectivityStatus;
        return { status: refreshed?.status, commercialModel: refreshed?.commercialModel, errors: response.data?.errors };
      } catch (error) {
        const errors = getResponseError(error)?.data?.errors;
        if (!errors) {
          throw error;
        }
        return { errors };
      }
    };

    // A hub older than this platform rejects the fields it does not know yet: drop each one in turn rather than
    // reporting a healthy registration as lost connectivity.
    const attempt = async (withPlatformContract: boolean, withCommercialModel: boolean): Promise<RefreshRegistrationStatusResult> => {
      const { status, commercialModel, errors } = await refresh(withPlatformContract, withCommercialModel);
      if (status) {
        return { status, commercialModel: withCommercialModel ? toCommercialModel(commercialModel) : null };
      }
      if (withCommercialModel && isFieldRejected(errors, COMMERCIAL_MODEL_UNKNOWN_FIELD)) {
        if (!isCommercialModelFallbackLogged) {
          logApp.warn('[XTMH] XTM Hub does not expose the commercial model yet, refreshing the connectivity without it');
          isCommercialModelFallbackLogged = true;
        }
        return attempt(withPlatformContract, false);
      }
      if (withPlatformContract && isFieldRejected(errors, PLATFORM_CONTRACT_UNKNOWN_FIELD)) {
        if (!isPlatformContractFallbackLogged) {
          logApp.warn('[XTMH] XTM Hub does not accept the platform edition yet, refreshing the connectivity without it');
          isPlatformContractFallbackLogged = true;
        }
        return attempt(false, withCommercialModel);
      }
      logApp.warn('XTM Hub sent an error', { codes: hubErrorCodes(errors) });
      return INACTIVE_REFRESH_RESULT;
    };

    try {
      return await attempt(true, true);
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return INACTIVE_REFRESH_RESULT;
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
