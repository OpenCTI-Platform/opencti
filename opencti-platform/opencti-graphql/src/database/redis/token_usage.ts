import nconf from 'nconf';
import { getClientBase } from '../redis';
import { logApp } from '../../config/conf';
import type { UserApiToken } from '../../types/user';

const tokenUsageLastUpdateTime = Symbol('lastChecked');
type TokenWithLastChecked = UserApiToken & { [tokenUsageLastUpdateTime]?: number };

const REDIS_TOKEN_USAGE_PREFIX = 'token_usage:';
// Only update activity every 15 minutes by default
const REDIS_THROTTLE_MILLIS = 1000 * (nconf.get('app:token_activity_period') ?? 60);

export type TokenUsage = { tokenId: string; last_check: number };

export const updateTokenUsage = async (tokenRaw: UserApiToken) => {
  const token = tokenRaw as TokenWithLastChecked;
  const key = `${REDIS_TOKEN_USAGE_PREFIX}${token.id}`;
  const now = Date.now();
  const lastChecked = token[tokenUsageLastUpdateTime] ?? 0;
  if ((now - lastChecked) > REDIS_THROTTLE_MILLIS) {
    try {
      const data: TokenUsage = { tokenId: token.id, last_check: now };
      const redis = getClientBase();
      await redis.set(key, JSON.stringify(data));
      token[tokenUsageLastUpdateTime] = now;
    } catch (err) {
      logApp.error('Error updating token usage in Redis', { cause: err });
    }
  }
};

export const getTokensUsage = async (tokenIds: string[]): Promise<Record<string, string>> => {
  if (tokenIds.length === 0) {
    return {};
  }
  const tokenKeys = tokenIds.map((tokenId) => `${REDIS_TOKEN_USAGE_PREFIX}${tokenId}`);
  const tokens = await getClientBase().mget(tokenKeys);
  return Object.fromEntries(
    tokens
      .filter((token) => token !== null)
      .map((token) => {
        const tokenData = JSON.parse(token as string) as TokenUsage;
        return [tokenData.tokenId, new Date(tokenData.last_check).toISOString()];
      }),
  );
};
