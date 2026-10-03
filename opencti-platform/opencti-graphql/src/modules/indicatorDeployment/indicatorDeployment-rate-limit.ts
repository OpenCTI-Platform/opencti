import { RateLimiterMemory, RateLimiterRes } from 'rate-limiter-flexible';
import conf from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import type { AuthUser } from '../../types/user';

// Per user and per API node limits protecting the write-back mutations used by stream connectors.
export const DEPLOYMENT_RATE_LIMIT_SINGLE = 'single';
export const DEPLOYMENT_RATE_LIMIT_BATCH = 'batch';
export const DEPLOYMENT_RATE_LIMIT_HITS = 'hits';
type DeploymentRateLimitKind = typeof DEPLOYMENT_RATE_LIMIT_SINGLE | typeof DEPLOYMENT_RATE_LIMIT_BATCH | typeof DEPLOYMENT_RATE_LIMIT_HITS;

const toPositiveInteger = (value: unknown, fallback: number) => {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
};

const limiters: Record<DeploymentRateLimitKind, RateLimiterMemory> = {
  [DEPLOYMENT_RATE_LIMIT_SINGLE]: new RateLimiterMemory({
    points: toPositiveInteger(conf.get('indicator_deployment:report_rate_limit'), 200),
    duration: 1,
  }),
  [DEPLOYMENT_RATE_LIMIT_BATCH]: new RateLimiterMemory({
    points: toPositiveInteger(conf.get('indicator_deployment:batch_rate_limit'), 20),
    duration: 1,
  }),
  [DEPLOYMENT_RATE_LIMIT_HITS]: new RateLimiterMemory({
    points: toPositiveInteger(conf.get('indicator_deployment:hits_rate_limit'), 200),
    duration: 1,
  }),
};

export const consumeDeploymentRateLimit = async (kind: DeploymentRateLimitKind, user: AuthUser) => {
  try {
    await limiters[kind].consume(user.id);
  } catch (error) {
    if (error instanceof RateLimiterRes) {
      throw FunctionalError('Too many requests', { kind, retry_after_ms: error.msBeforeNext });
    }
    throw error;
  }
};
