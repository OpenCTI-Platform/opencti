import { getHttpClient, getResponseError } from '../../../utils/http-client';
import conf, { logApp, PLATFORM_VERSION } from '../../../config/conf';
import type { Success } from '../../../generated/graphql';
import { type NewsFeedItemMetadata, NewsFeedItemType } from './news-feed/news-feed-types';
import { getXtmHubKey, type XtmHubPublicJwk } from './xtm-hub-key';
import { HUB_OPENCTI_IDENTIFIER } from './xtm-hub-identifier';

type RegistrationStatus = 'active' | 'inactive' | 'not_found';
export type HubPlatformContract = 'CE' | 'EE';
export type HubCommercialModel = 'saas' | 'other';

export interface RefreshRegistrationStatusResult {
  status: RegistrationStatus;
  // Null when the hub does not return it (unreachable hub, error, unknown value).
  commercialModel: HubCommercialModel | null;
  // Name of the hub organization the platform is registered in. Null when the hub does not return it.
  organizationName: string | null;
}

interface HubGraphQLError {
  message?: string;
  extensions?: { code?: string };
}

interface HubRefreshAnswer {
  status?: RegistrationStatus;
  commercialModel?: unknown;
  organizationName?: unknown;
  errors?: HubGraphQLError[];
}

// How this platform authenticates a call to XTM Hub: with its key once XTM Hub has enrolled it, with the
// registration token before. Never both: an enrolled platform does not fall back to the token.
export type XtmHubCredentials = { kind: 'key' } | { kind: 'token'; token: string };

export const XTM_HUB_ASSERTION_HEADER = 'XTM-Hub-Platform-Assertion';
const XTM_HUB_TOKEN_HEADER = 'XTM-Hub-Platform-Token';
const XTM_HUB_PLATFORM_ID_HEADER = 'XTM-Hub-Platform-Id';

const tokenHeaders = (platformId: string, token: string): Record<string, string> => ({
  [XTM_HUB_TOKEN_HEADER]: token,
  [XTM_HUB_PLATFORM_ID_HEADER]: platformId,
});

// A new assertion for every call: XTM Hub accepts each one once (jti) and for 60 seconds.
// No htu: these calls open no single resource.
const assertionHeaders = async (platformId: string): Promise<Record<string, string>> => {
  const key = await getXtmHubKey();
  return { [XTM_HUB_ASSERTION_HEADER]: await key.signAssertion({ platformId }) };
};

const platformHeaders = async (platformId: string, credentials: XtmHubCredentials): Promise<Record<string, string>> => (
  credentials.kind === 'key' ? assertionHeaders(platformId) : tokenHeaders(platformId, credentials.token)
);

// The refusals of a platform credential XTM Hub answers, by error code: the one place they are read.
// assertion_invalid: a signature, type, audience, expiry or replayed jti XTM Hub refused.
// key_mismatch: the key that signed is not the one XTM Hub enrolled (the encryption key or the key version changed).
// token_refused: XTM Hub knows no registration under this token.
// token_path_closed: XTM Hub no longer accepts platform tokens.
export type XtmHubPlatformRefusal = 'assertion_invalid' | 'key_mismatch' | 'token_refused' | 'token_path_closed';
const PLATFORM_REFUSALS: Record<string, XtmHubPlatformRefusal> = {
  PLATFORM_ASSERTION_INVALID: 'assertion_invalid',
  PLATFORM_KEY_MISMATCH: 'key_mismatch',
  PLATFORM_TOKEN_REFUSED: 'token_refused',
  PLATFORM_TOKEN_PATH_CLOSED: 'token_path_closed',
};

// What XTM Hub answers an enrollment, with the same names as the other XTM products.
// enrolled: the key is stored (again, for a retry): the token can go.
// conflict: another key is enrolled for this registration.
// not_found: no registration matches the token.
// key_mismatch: the key that signed the assertion is not the public key sent.
// not_available: XTM Hub does not enroll keys yet.
// unknown_operation: XTM Hub is older than the enrollment.
// unreachable: a network failure, a timeout or a 5xx.
// refused: any other refusal or answer.
// not_available, unknown_operation and unreachable keep the token for a later try.
export type XtmHubEnrollmentOutcome = 'enrolled' | 'conflict' | 'not_found' | 'key_mismatch' | 'not_available'
  | 'unknown_operation' | 'unreachable' | 'refused';
const ENROLLMENT_STATUSES: XtmHubEnrollmentOutcome[] = ['enrolled', 'conflict', 'not_found', 'key_mismatch', 'not_available'];

// The one place the enrollment request is written: XTM Hub's enrollPlatformKey answers this document.
// The call carries the token headers, which name the registration, and an assertion signed with the key
// it enrolls, which proves this platform holds it.
const ENROLL_PLATFORM_KEY_MUTATION = `
  mutation EnrollPlatformKey($input: EnrollPlatformKeyInput!) {
    enrollPlatformKey(input: $input) {
      status
    }
  }
`;

// The code of a document XTM Hub's schema does not validate: an older XTM Hub without enrollPlatformKey.
const GRAPHQL_VALIDATION_FAILED = 'GRAPHQL_VALIDATION_FAILED';
const ENROLL_PLATFORM_KEY_UNKNOWN = ['Cannot query field "enrollPlatformKey" on type', 'Unknown type "EnrollPlatformKeyInput"'];

const INACTIVE_REFRESH_RESULT: RefreshRegistrationStatusResult = { status: 'inactive', commercialModel: null, organizationName: null };

// The input coercion error a hub older than the edition refresh (graphql-js 16) returns for the unknown field.
const PLATFORM_CONTRACT_UNKNOWN_FIELD = 'Field "platformContract" is not defined by type "RefreshPlatformRegistrationConnectivityStatusInput"';
// The validation error a hub older than the commercial model refresh (graphql-js 16) returns for the unknown selected field.
const COMMERCIAL_MODEL_UNKNOWN_FIELD = 'Cannot query field "commercialModel" on type';
// The validation error a hub older than the organization name refresh returns for the unknown selected field.
const ORGANIZATION_NAME_UNKNOWN_FIELD = 'Cannot query field "organizationName" on type';
const isFieldRejected = (errors: HubGraphQLError[] | undefined, fieldError: string) => (errors ?? [])
  .some((error) => typeof error?.message === 'string' && error.message.includes(fieldError));

// GraphQL input errors echo the submitted variables, the platform token included: never log their messages.
const hubErrorCodes = (errors?: HubGraphQLError[]) => (errors ?? [])
  .map((error) => error?.extensions?.code)
  .filter((code): code is string => typeof code === 'string');

const toPlatformRefusal = (errors?: HubGraphQLError[]): XtmHubPlatformRefusal | null => {
  const code = hubErrorCodes(errors).find((errorCode) => errorCode in PLATFORM_REFUSALS);
  return code ? PLATFORM_REFUSALS[code] : null;
};

const toEnrollmentOutcome = (status: unknown): XtmHubEnrollmentOutcome | null => {
  if (typeof status !== 'string') {
    return null;
  }
  const outcome = status.toLowerCase();
  return ENROLLMENT_STATUSES.find((known) => known === outcome) ?? null;
};

const toEnrollmentRefusal = (errors: HubGraphQLError[]): XtmHubEnrollmentOutcome => {
  const isUnknownOperation = hubErrorCodes(errors).includes(GRAPHQL_VALIDATION_FAILED)
    || ENROLL_PLATFORM_KEY_UNKNOWN.some((unknownError) => isFieldRejected(errors, unknownError));
  if (isUnknownOperation) {
    return 'unknown_operation';
  }
  const refusal = toPlatformRefusal(errors);
  if (refusal === 'key_mismatch') {
    return 'key_mismatch';
  }
  // No registration the token still opens: the same answer as a token XTM Hub does not know.
  if (refusal === 'token_refused' || refusal === 'token_path_closed') {
    return 'not_found';
  }
  return 'refused';
};

let isPlatformContractFallbackLogged = false;
let isCommercialModelFallbackLogged = false;
let isOrganizationNameFallbackLogged = false;

// The hub answers with its own CommercialModel enum: a value this platform does not know yet is ignored rather than stored.
const toCommercialModel = (value: unknown): HubCommercialModel | null => {
  if (typeof value !== 'string') {
    return null;
  }
  const commercialModel = value.toLowerCase();
  return commercialModel === 'saas' || commercialModel === 'other' ? commercialModel : null;
};

const toOrganizationName = (value: unknown): string | null => {
  if (typeof value !== 'string') {
    return null;
  }
  const organizationName = value.trim();
  return organizationName.length > 0 ? organizationName : null;
};

interface RefreshSelection {
  withPlatformContract: boolean;
  withCommercialModel: boolean;
  withOrganizationName: boolean;
}

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

export const xtmHubClient = {
  isBackendReachable: async (): Promise<{ isReachable: boolean }> => {
    try {
      const httpClient = getHttpClient({
        baseURL: HUB_BACKEND_URL,
        trusted: true,
        responseType: 'json',
      });

      const response = await httpClient.head('/health', { timeout: 5000 });
      return { isReachable: response.status >= 200 && response.status < 300 };
    } catch (_error) {
      return { isReachable: false };
    }
  },
  refreshRegistrationStatus: async ({ platformId, credentials, platformVersion, platformContract }: {
    platformId: string;
    credentials: XtmHubCredentials;
    platformVersion: string;
    platformContract: HubPlatformContract;
  }): Promise<RefreshRegistrationStatusResult> => {
    const buildQuery = ({ withCommercialModel, withOrganizationName }: RefreshSelection) => {
      const selectedFields = [
        'status',
        ...(withCommercialModel ? ['commercialModel'] : []),
        ...(withOrganizationName ? ['organizationName'] : []),
      ];
      return `
      mutation RefreshPlatformRegistrationConnectivityStatus($input: RefreshPlatformRegistrationConnectivityStatusInput!) {
        refreshPlatformRegistrationConnectivityStatus(input: $input) {
          ${selectedFields.join('\n          ')}
        }
      }
    `;
    };

    // Before enrollment the token travels in the input, as it always has. Once enrolled, the call is signed
    // and the input carries no token.
    const input = {
      platformId,
      ...(credentials.kind === 'token' ? { token: credentials.token } : {}),
      platformVersion,
      platformIdentifier: HUB_OPENCTI_IDENTIFIER,
    };
    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      trusted: true,
      responseType: 'json',
    });
    const refresh = async (selection: RefreshSelection): Promise<HubRefreshAnswer> => {
      const variables = { input: selection.withPlatformContract ? { ...input, platformContract } : input };
      // Every attempt is a call of its own: a retry without a field signs a new assertion.
      const headers = credentials.kind === 'key' ? await assertionHeaders(platformId) : {};
      try {
        const response = await httpClient.post('/graphql-api', { query: buildQuery(selection), variables }, { headers });
        const refreshed = response.data?.data?.refreshPlatformRegistrationConnectivityStatus;
        return {
          status: refreshed?.status,
          commercialModel: refreshed?.commercialModel,
          organizationName: refreshed?.organizationName,
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

    // A hub older than this platform rejects the fields it does not know yet: drop each one in turn rather than
    // reporting a healthy registration as lost connectivity.
    const attempt = async (selection: RefreshSelection): Promise<RefreshRegistrationStatusResult> => {
      const { status, commercialModel, organizationName, errors } = await refresh(selection);
      if (status) {
        return {
          status,
          commercialModel: selection.withCommercialModel ? toCommercialModel(commercialModel) : null,
          organizationName: selection.withOrganizationName ? toOrganizationName(organizationName) : null,
        };
      }
      // graphql-js reports every unknown selected field at once: drop all the rejected ones in a single retry.
      const isOrganizationNameRejected = selection.withOrganizationName && isFieldRejected(errors, ORGANIZATION_NAME_UNKNOWN_FIELD);
      const isCommercialModelRejected = selection.withCommercialModel && isFieldRejected(errors, COMMERCIAL_MODEL_UNKNOWN_FIELD);
      if (isOrganizationNameRejected || isCommercialModelRejected) {
        if (isCommercialModelRejected && !isCommercialModelFallbackLogged) {
          logApp.warn('[XTMH] XTM Hub does not expose the commercial model yet, refreshing the connectivity without it');
          isCommercialModelFallbackLogged = true;
        }
        if (isOrganizationNameRejected && !isOrganizationNameFallbackLogged) {
          logApp.warn('[XTMH] XTM Hub does not expose the organization name yet, refreshing the connectivity without it');
          isOrganizationNameFallbackLogged = true;
        }
        return attempt({
          ...selection,
          withCommercialModel: selection.withCommercialModel && !isCommercialModelRejected,
          withOrganizationName: selection.withOrganizationName && !isOrganizationNameRejected,
        });
      }
      if (selection.withPlatformContract && isFieldRejected(errors, PLATFORM_CONTRACT_UNKNOWN_FIELD)) {
        if (!isPlatformContractFallbackLogged) {
          logApp.warn('[XTMH] XTM Hub does not accept the platform edition yet, refreshing the connectivity without it');
          isPlatformContractFallbackLogged = true;
        }
        return attempt({ ...selection, withPlatformContract: false });
      }
      logApp.warn('XTM Hub sent an error', { codes: hubErrorCodes(errors), refusal: toPlatformRefusal(errors) });
      return INACTIVE_REFRESH_RESULT;
    };

    try {
      return await attempt({ withPlatformContract: true, withCommercialModel: true, withOrganizationName: true });
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return INACTIVE_REFRESH_RESULT;
    }
  },
  autoRegister: async (platform: { platformId: string; credentials: XtmHubCredentials; platformUrl: string; platformTitle: string },
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
      trusted: true,
      responseType: 'json',
      headers: { 'Content-Type': 'application/json' },
    });

    try {
      const headers = await platformHeaders(platform.platformId, platform.credentials);
      const response = await httpClient.post('/graphql-api', { query, variables }, { headers });
      const { data, errors } = response.data;
      if ((errors?.length ?? 0) > 0 || !data?.autoRegisterPlatform?.success) {
        logApp.warn('XTM sent an error', { reason: errors?.[0] });
        return { success: false };
      }
      return data?.autoRegisterPlatform;
    } catch (error) {
      logApp.warn('XTM Hub is unreachable', { reason: error });
      return { success: false };
    }
  },
  consumeProvisionedNewsFeedItems: async (platformId: string, credentials: XtmHubCredentials): Promise<ConsumeProvisionedNewsFeedItemsResponse> => {
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
      trusted: true,
      responseType: 'json',
      headers: { 'Content-Type': 'application/json' },
    });

    const emptyResponse: ConsumeProvisionedNewsFeedItemsResponse = { news_feed_items: [], available_news_feed_types: [] };

    try {
      const headers = await platformHeaders(platformId, credentials);
      const response = await httpClient.post('/graphql-api', { query: mutation }, { headers });
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
  contactUs: async (platform: { platformId: string; credentials: XtmHubCredentials }, message: string): Promise<Success> => {
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
      trusted: true,
      responseType: 'json',
      headers: { 'Content-Type': 'application/json' },
    });

    try {
      const headers = await platformHeaders(platform.platformId, platform.credentials);
      const response = await httpClient.post('/graphql-api', { query, variables }, { headers });
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
  // Asks XTM Hub to enroll this platform's public key for the registration the token belongs to.
  // Only XTM Hub's answer is read: recording the enrollment and forgetting the token are the caller's.
  enrollPlatformKey: async (
    platform: { platformId: string; token: string },
    publicJwk: XtmHubPublicJwk,
    assertion: string,
  ): Promise<XtmHubEnrollmentOutcome> => {
    const httpClient = getHttpClient({
      baseURL: HUB_BACKEND_URL,
      trusted: true,
      responseType: 'json',
      headers: { 'Content-Type': 'application/json' },
    });
    const headers = { ...tokenHeaders(platform.platformId, platform.token), [XTM_HUB_ASSERTION_HEADER]: assertion };
    const variables = { input: { publicKey: publicJwk } };

    let answer: { data?: { enrollPlatformKey?: { status?: unknown } } | null; errors?: HubGraphQLError[] } | undefined;
    try {
      const response = await httpClient.post('/graphql-api', { query: ENROLL_PLATFORM_KEY_MUTATION, variables }, { headers });
      answer = response.data;
    } catch (error) {
      const responseError = getResponseError(error);
      if (!responseError || responseError.status >= 500) {
        logApp.warn('[XTMH] XTM Hub is unreachable, the platform key is not enrolled', { status: responseError?.status });
        return 'unreachable';
      }
      answer = responseError.data;
    }

    const errors = answer?.errors ?? [];
    if (errors.length > 0) {
      const outcome = toEnrollmentRefusal(errors);
      logApp.warn('[XTMH] XTM Hub did not enroll the platform key', { outcome, codes: hubErrorCodes(errors) });
      return outcome;
    }
    const outcome = toEnrollmentOutcome(answer?.data?.enrollPlatformKey?.status);
    if (!outcome) {
      logApp.warn('[XTMH] XTM Hub answered the platform key enrollment with an unknown status');
      return 'refused';
    }
    return outcome;
  },
};
