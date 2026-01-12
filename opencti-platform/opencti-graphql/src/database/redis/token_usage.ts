import { LRUCache } from 'lru-cache';
import { getClientBase } from '../redis';
import { DateTime } from 'luxon';
import { logApp } from '../../config/conf';
import nconf from 'nconf';

const REDIS_TOKEN_USAGE_PREFIX = 'token_usage:';
// Only update activity every 15 minutes by default
const REDIS_THROTTLE_MIN = nconf.get('app:token_activity_period') ?? 15;

export type TokenUsage = { user: string; token: string; last_check: string };

// L1 Cache to avoid hitting Redis for every request
const l1Cache = new LRUCache<string, DateTime>({
  max: 5000,
  // We manage TTL validity manually to ensure consistency with Date.now()
  // ttl: REDIS_THROTTLE_MS,
});

export const updateTokenUsage = async (userId: string, tokenId: string) => {
  const redis = getClientBase();
  const key = `${REDIS_TOKEN_USAGE_PREFIX}${tokenId}`;
  const now = DateTime.now().toUTC();
  try {
    // Check L1 Cache first
    const l1LastChecked = l1Cache.get(key);
    if (l1LastChecked && now.diff(l1LastChecked, 'minutes').minutes < REDIS_THROTTLE_MIN) {
      return;
    }
    const data: TokenUsage = { user: userId, token: tokenId, last_check: now.toISO() };
    await redis.set(key, JSON.stringify(data));
    // Update L1 Cache with current check time
    l1Cache.set(key, now);
  } catch (err) {
    logApp.error('Error updating token usage in Redis', { cause: err });
  }
};

export const getTokensUsage = async (tokenIds: string[]): Promise<Record<string, string>> => {
  const result: Record<string, string> = {};
  if (tokenIds.length === 0) {
    return result;
  }
  const tokenKeys = tokenIds.map((tokenId) => `${REDIS_TOKEN_USAGE_PREFIX}${tokenId}`);
  const tokens = await getClientBase().mget(tokenKeys);
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token !== null) {
      const tokenData = JSON.parse(token) as TokenUsage;
      result[tokenData.token] = tokenData.last_check;
    }
  }
  return result;
};
