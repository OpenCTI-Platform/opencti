import conf, { logApp } from '../../../config/conf';
import { getHttpClient, getResponseError } from '../../../utils/http-client';
import type {
  PulseBatch,
  PulseHubBenchmarkResult,
  PulseHubDigest,
  PulseHubLookupResult,
  PulseHubStatus,
  PulseHubTrendingResult,
  PulseObjectType,
  PulsePeriodValue,
  PulseRegionBucketValue,
  PulseSectorBucketValue,
} from '../pulse/pulse-types';

export interface PulseHubPlatform {
  platformId: string;
  platformToken: string;
}

export type PulseHubErrorCode = 'hub_unreachable' | 'contribution_required' | 'rate_limited' | 'unauthenticated' | 'forbidden' | 'bad_request' | 'unexpected';

export class PulseHubError extends Error {
  readonly code: PulseHubErrorCode;

  readonly retryAfterSeconds: number | undefined;

  constructor(code: PulseHubErrorCode, message: string, retryAfterSeconds?: number) {
    super(message);
    this.name = 'PulseHubError';
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

const PULSE_HUB_TIMEOUT = 30000;

// Read at call time: tests and operators can point Threat Pulse to another Hub without a restart of the module.
const getHubBackendUrl = (): string => conf.get('xtm:xtmhub_api_override_url') ?? conf.get('xtm:xtmhub_url');

const HUB_ERROR_CODES: Record<string, PulseHubErrorCode> = {
  PULSE_CONTRIBUTION_REQUIRED: 'contribution_required',
  PULSE_RATE_LIMITED: 'rate_limited',
  UNAUTHENTICATED: 'unauthenticated',
  FORBIDDEN: 'forbidden',
  BAD_USER_INPUT: 'bad_request',
};

const toPulseHubError = (errors: Array<{ message?: string; extensions?: { code?: string; retry_after_seconds?: number } }>): PulseHubError => {
  const [first] = errors;
  const code = HUB_ERROR_CODES[first?.extensions?.code ?? ''] ?? 'unexpected';
  return new PulseHubError(code, first?.message ?? 'XTM Hub rejected the Threat Pulse request', first?.extensions?.retry_after_seconds);
};

const pulseRequest = async <T>(platform: PulseHubPlatform, operation: string, query: string, variables: Record<string, unknown>): Promise<T> => {
  const httpClient = getHttpClient({
    baseURL: getHubBackendUrl(),
    responseType: 'json',
    timeout: PULSE_HUB_TIMEOUT,
    headers: {
      'Content-Type': 'application/json',
      'XTM-Hub-Platform-Id': platform.platformId,
      'XTM-Hub-Platform-Token': platform.platformToken,
    },
  });
  let body: { data?: Record<string, T>; errors?: Array<{ message?: string; extensions?: { code?: string; retry_after_seconds?: number } }> };
  try {
    const response = await httpClient.post('/graphql-api', { query, variables });
    body = response.data;
  } catch (error) {
    const responseError = getResponseError(error);
    if (responseError?.data?.errors?.length) {
      throw toPulseHubError(responseError.data.errors);
    }
    logApp.warn('[XTMH] Threat Pulse request failed, XTM Hub is unreachable', { operation, status: responseError?.status });
    throw new PulseHubError('hub_unreachable', 'XTM Hub is unreachable');
  }
  if (body?.errors && body.errors.length > 0) {
    throw toPulseHubError(body.errors);
  }
  const result = body?.data?.[operation];
  if (result === undefined || result === null) {
    throw new PulseHubError('unexpected', `XTM Hub returned no result for ${operation}`);
  }
  return result;
};

const LOOKUP_FIELDS = `
  hash
  published
  prevalence_bucket
  platforms_bucket
  first_seen_network
  last_seen_network
  trend
  trend_series
  sector_trend
  sector_platforms_bucket
`;

export const xtmHubPulseClient = {
  salt: async (platform: PulseHubPlatform, day: string): Promise<{ day: string; salt: string }> => {
    const query = 'query PulseSalt($day: String!) { pulseSalt(day: $day) { day salt } }';
    return pulseRequest(platform, 'pulseSalt', query, { day });
  },
  status: async (platform: PulseHubPlatform): Promise<PulseHubStatus> => {
    const query = `query PulseStatus {
      pulseStatus {
        day k_threshold retention_months contributors_bucket read_access last_contribution_day
        contribution_status read_access_until contribution_window_days contribution_grace_days
      }
    }`;
    return pulseRequest(platform, 'pulseStatus', query, {});
  },
  // The preview download: the request carries the coarse buckets of the platform and nothing about its objects.
  digest: async (platform: PulseHubPlatform, input: {
    day: string;
    sector_bucket: PulseSectorBucketValue | null;
    region_bucket: PulseRegionBucketValue | null;
  }): Promise<PulseHubDigest> => {
    const query = `query PulseDigest($input: PulseDigestInput!) {
      pulseDigest(input: $input) {
        day sector_bucket region_bucket
        items { hash object_type prevalence_bucket trend }
        trending { period locked_count items { rank hash object_type prevalence_bucket trend } }
      }
    }`;
    return pulseRequest(platform, 'pulseDigest', query, { input });
  },
  push: async (platform: PulseHubPlatform, batch: PulseBatch): Promise<{ accepted: number; day: string }> => {
    const query = 'mutation PushPulse($input: PushPulseInput!) { pushPulse(input: $input) { accepted day } }';
    return pulseRequest(platform, 'pushPulse', query, { input: batch });
  },
  lookup: async (platform: PulseHubPlatform, input: { day: string; object_type: PulseObjectType; hashes: string[] }): Promise<PulseHubLookupResult[]> => {
    const query = `query PulseLookup($input: PulseLookupInput!) { pulseLookup(input: $input) { ${LOOKUP_FIELDS} } }`;
    return pulseRequest(platform, 'pulseLookup', query, { input });
  },
  trending: async (platform: PulseHubPlatform, input: {
    day: string;
    period: PulsePeriodValue;
    sector_bucket: PulseSectorBucketValue | null;
    region_bucket: PulseRegionBucketValue | null;
    object_types: PulseObjectType[] | null;
    first: number;
  }): Promise<PulseHubTrendingResult> => {
    const query = `query PulseTrending($input: PulseTrendingInput!) {
      pulseTrending(input: $input) {
        day period sector_bucket region_bucket
        items { hash object_type platforms_bucket prevalence_bucket trend growth first_seen_network }
      }
    }`;
    return pulseRequest(platform, 'pulseTrending', query, { input });
  },
  benchmark: async (platform: PulseHubPlatform, input: { day: string; period: PulsePeriodValue }): Promise<PulseHubBenchmarkResult> => {
    const query = `query PulseBenchmark($input: PulseBenchmarkInput!) {
      pulseBenchmark(input: $input) {
        period sector_bucket region_bucket sector_platforms_bucket
        metrics { object_type event_kind platform_count sector_platform_count sector_median network_median }
        top_items { hash object_type platform_count sector_median ratio }
      }
    }`;
    return pulseRequest(platform, 'pulseBenchmark', query, { input: { platformId: platform.platformId, ...input } });
  },
  purge: async (platform: PulseHubPlatform): Promise<{ success: boolean; deleted_records: number }> => {
    const query = 'mutation PulsePurge($platformId: String!) { pulsePurge(platformId: $platformId) { success deleted_records } }';
    return pulseRequest(platform, 'pulsePurge', query, { platformId: platform.platformId });
  },
};
