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

// The input coercion error a hub older than the edition refresh (graphql-js 16) returns for the unknown field.
const PLATFORM_CONTRACT_UNKNOWN_FIELD = 'Field "platformContract" is not defined by type "RefreshPlatformRegistrationConnectivityStatusInput"';
const isPlatformContractRejected = (errors?: HubGraphQLError[]) => (errors ?? [])
  .some((error) => typeof error?.message === 'string' && error.message.includes(PLATFORM_CONTRACT_UNKNOWN_FIELD));

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

export interface HubIntegrationCoverageInput {
  objectTypes?: string[];
  sectors?: string[];
  regions?: string[];
  integrationTypes?: string[];
  searchTerm?: string;
  first?: number;
}

export interface HubIntegrationCoverageMatch {
  id: string;
  slug: string;
  name: string;
  short_description: string | null;
  integration_type: string;
  license_type: string | null;
  verified: boolean | null;
  manager_supported: boolean | null;
  object_types: string[];
  sectors: string[];
  regions: string[];
  coverage_inferred: boolean;
  matched_object_types: string[];
  matched_sectors: string[];
  matched_regions: string[];
  score: number;
}

export interface HubIntegrationCoverageResult {
  status: 'ok' | 'unreachable' | 'error';
  matches: HubIntegrationCoverageMatch[];
  // More integrations matched than XTM Hub ranks: the matches are its first candidates, not a complete ranking
  truncated: boolean;
}

const HUB_BACKEND_URL = conf.get('xtm:xtmhub_api_override_url') ?? conf.get('xtm:xtmhub_url');
const HUB_OPENCTI_IDENTIFIER = 'opencti';
const HUB_COVERAGE_SEARCH_TIMEOUT = 15000;

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
  // Catalog search by coverage facets (object types, sectors, regions), used by the collection gaps of Source Intelligence
  integrationsByCoverage: async (
    platform: { platformId: string; platformToken: string } | null,
    input: HubIntegrationCoverageInput,
  ): Promise<HubIntegrationCoverageResult> => {
    const query = `
      query IntegrationsByCoverage($input: IntegrationCoverageSearchInput!) {
        integrationsByCoverage(input: $input) {
          matches {
            id
            slug
            name
            short_description
            integration_type
            license_type
            verified
            manager_supported
            object_types
            sectors
            regions
            coverage_inferred
            matched_object_types
            matched_sectors
            matched_regions
            score
          }
          truncated
        }
      }
    `;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (platform) {
      headers['XTM-Hub-Platform-Id'] = platform.platformId;
      headers['XTM-Hub-Platform-Token'] = platform.platformToken;
    }
    const httpClient = getHttpClient({ baseURL: HUB_BACKEND_URL, responseType: 'json', headers });
    try {
      const response = await httpClient.post('/graphql-api', { query, variables: { input } }, { timeout: HUB_COVERAGE_SEARCH_TIMEOUT });
      const { data, errors } = response.data;
      if ((errors?.length ?? 0) > 0) {
        logApp.warn('XTM Hub integrationsByCoverage error', { reason: errors?.[0] });
        return { status: 'error', matches: [], truncated: false };
      }
      return {
        status: 'ok',
        matches: data?.integrationsByCoverage?.matches ?? [],
        truncated: data?.integrationsByCoverage?.truncated === true,
      };
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return { status: 'unreachable', matches: [], truncated: false };
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
