import { RateLimiterMemory, RateLimiterRes } from 'rate-limiter-flexible';
import conf from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import type { AuthUser } from '../../types/user';

// Per user limits protecting the API node that runs the write-back mutations of the stream connectors. They are
// counted in the memory of each node, as the other rate limits of the platform: with several API nodes, an account
// gets the limit on each node.
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
