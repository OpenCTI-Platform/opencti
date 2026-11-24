import { getClientBase } from '../../database/redis';
import type { PresenceOrigin } from './session-presence-types';

// Session presence shared by all the platform nodes.
// Every WebSocket of a session holds a lease, renewed by the node owning the socket, that expires if the node stops renewing it
// (crash, network loss). The sessions to check are listed with the time of their check, so a pending logout outlives its node.
// That list is only a hint: the deadline of a session is kept in its own slot, and read by the check in the same script as its leases.
// The keys of a session share a hash tag, so that each script stays in a single slot on Redis Cluster.
// Times come from Redis: a clock skew between the nodes cannot expire a live lease.

const leasesKey = (sessionId: string) => `session_presence:{${sessionId}}:leases`;
const closingKey = (sessionId: string) => `session_presence:{${sessionId}}:closing`;
const originKey = (sessionId: string) => `session_presence:{${sessionId}}:origin`;
const checkAtKey = (sessionId: string) => `session_presence:{${sessionId}}:check_at`;
const DUE_SESSIONS_KEY = 'session_presence_due';

const REDIS_NOW = `
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
`;

// KEYS: leases, closing, origin, check_at. ARGV: lease ttl, keys ttl, grace period, origin (empty to keep it), connection ids...
// Refused while the session is being logged out. The deadline of the session is only pushed forward, to the end of
// the grace period following its leases. Returns that deadline, -1 when refused.
const SAVE_LEASES_SCRIPT = `
if redis.call('EXISTS', KEYS[2]) == 1 then
  return -1
end
${REDIS_NOW}
local expiry = now + tonumber(ARGV[1])
for i = 5, #ARGV do
  redis.call('ZADD', KEYS[1], expiry, ARGV[i])
end
redis.call('PEXPIRE', KEYS[1], ARGV[2])
if ARGV[4] ~= '' then
  redis.call('SET', KEYS[3], ARGV[4], 'PX', ARGV[2])
else
  redis.call('PEXPIRE', KEYS[3], ARGV[2])
end
local checkAt = math.max(tonumber(redis.call('GET', KEYS[4]) or 0), expiry + tonumber(ARGV[3]))
redis.call('SET', KEYS[4], checkAt, 'PX', ARGV[2])
return checkAt
`;

// KEYS: leases, check_at. ARGV: connection id, keys ttl, grace period.
// When no live lease is left, the deadline of the session is the end of the grace period starting now.
// Returns the number of live leases left, and that deadline (0 while a lease is live).
const REMOVE_LEASE_SCRIPT = `
${REDIS_NOW}
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local liveLeases = redis.call('ZCARD', KEYS[1])
if liveLeases > 0 then
  return { liveLeases, 0 }
end
local checkAt = now + tonumber(ARGV[3])
redis.call('SET', KEYS[2], checkAt, 'PX', ARGV[2])
return { 0, checkAt }
`;

// KEYS: leases, closing, check_at. ARGV: closing ttl (0 to release the session without logging it out), grace period.
// The session is kept until its deadline, whatever the time it was listed for. Past it, when no live lease is left,
// the session is marked as closing and its keys are dropped in the same step: a tab coming back from now on is refused,
// so it cannot be registered on a session about to be destroyed.
// Returns { 1, time of the next check } while the session is kept, { 0, now } otherwise.
const CHECK_LEASES_SCRIPT = `
${REDIS_NOW}
local checkAt = tonumber(redis.call('GET', KEYS[3]) or 0)
if now < checkAt then
  return { 1, checkAt }
end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) > 0 then
  local latest = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
  return { 1, tonumber(latest[2]) + tonumber(ARGV[2]) }
end
if tonumber(ARGV[1]) > 0 then
  redis.call('SET', KEYS[2], '1', 'PX', ARGV[1])
end
redis.call('DEL', KEYS[1], KEYS[3])
return { 0, now }
`;

// Leases are written for the connections of a session, the origin only when a connection opens.
// Returns the deadline of the session, or undefined when the session is being logged out.
export const saveSessionLeases = async (
  sessionId: string,
  connectionIds: string[],
  leaseTtl: number,
  keysTtl: number,
  gracePeriod: number,
  origin?: PresenceOrigin,
) => {
  const keys = [leasesKey(sessionId), closingKey(sessionId), originKey(sessionId), checkAtKey(sessionId)];
  const args = [leaseTtl, keysTtl, gracePeriod, origin ? JSON.stringify(origin) : '', ...connectionIds];
  const checkAt = Number(await getClientBase().eval(SAVE_LEASES_SCRIPT, keys.length, ...keys, ...args));
  return checkAt < 0 ? undefined : checkAt;
};

export const removeSessionLease = async (sessionId: string, connectionId: string, keysTtl: number, gracePeriod: number) => {
  const keys = [leasesKey(sessionId), checkAtKey(sessionId)];
  const [liveLeases, checkAt] = await getClientBase().eval(REMOVE_LEASE_SCRIPT, keys.length, ...keys, connectionId, keysTtl, gracePeriod) as [number, number];
  return { liveLeases: Number(liveLeases), checkAt: Number(checkAt) };
};

export const checkSessionLeases = async (sessionId: string, closingTtl: number, gracePeriod: number) => {
  const keys = [leasesKey(sessionId), closingKey(sessionId), checkAtKey(sessionId)];
  const [isKept, time] = await getClientBase().eval(CHECK_LEASES_SCRIPT, keys.length, ...keys, closingTtl, gracePeriod) as [number, number];
  return { isAlive: Number(isKept) === 1, time: Number(time) };
};

// The check time of a session is only pushed forward ('GT') when leases are renewed,
// and only brought forward ('LT') when its last lease is removed. A check made too early only reschedules the session.
export const scheduleSessionCheck = async (sessionId: string, checkTime: number, mode: 'GT' | 'LT') => {
  await getClientBase().zadd(DUE_SESSIONS_KEY, mode, checkTime, sessionId);
};

export const findDueSessions = async (limit: number) => {
  const [seconds, microseconds] = await getClientBase().time();
  const now = Number(seconds) * 1000 + Math.floor(Number(microseconds) / 1000);
  return getClientBase().zrangebyscore(DUE_SESSIONS_KEY, '-inf', now, 'LIMIT', 0, limit);
};

export const findSessionOrigin = async (sessionId: string): Promise<PresenceOrigin | undefined> => {
  const origin = await getClientBase().get(originKey(sessionId));
  return origin ? JSON.parse(origin) : undefined;
};

// Once checked, a session leaves the due list with its origin. Its closing mark expires by itself.
export const releaseSessionPresence = async (sessionId: string) => {
  await getClientBase().del(originKey(sessionId));
  await getClientBase().zrem(DUE_SESSIONS_KEY, sessionId);
};
