import { v4 as uuidv4 } from 'uuid';
import conf, { getStoppingState, logApp } from '../../config/conf';
import { getClusterInstances } from '../../database/redis';
import type { PresenceOrigin } from './session-presence-types';
import { removeSessionLease, saveSessionLeases, scheduleSessionCheck } from './session-presence-store';

// Logout a session once its last browser tab is gone.
// Every authenticated tab keeps a GraphQL WebSocket open for its whole life (root `me` subscription),
// so the session is considered abandoned when none of its sockets is alive for the grace period.
// Each socket holds a lease in Redis, renewed by its node: the presence is shared by all the nodes,
// and the leases of a crashed node expire.

const SESSION_PRESENCE_GRACE_PERIOD: number = conf.get('app:session_presence:grace_period') ?? 30000;
const SESSION_PRESENCE_LEASE_TTL: number = conf.get('app:session_presence:lease_ttl') ?? 30000;
const LEASE_RENEW_INTERVAL = Math.floor(SESSION_PRESENCE_LEASE_TTL / 3);
// The origin of a session is kept until its logout: after its last lease, the grace period and the time to sweep it
const PRESENCE_KEYS_TTL = SESSION_PRESENCE_LEASE_TTL + SESSION_PRESENCE_GRACE_PERIOD + 10 * 60 * 1000;

// connection id -> session id, for the sockets of this node
const nodeConnections = new Map<string, string>();
let renewTimer: NodeJS.Timeout | undefined;

// Only the nodes serving the API hold WebSockets: manager-only nodes are not counted.
// A node of a previous version doesn't tell, so it is counted. A starting node is listed before it serves the API,
// a stopped one stays listed until its registration expires: both pause the feature meanwhile.
export const isSessionPresenceSupported = async () => {
  const instances = await getClusterInstances();
  const apiNodes = instances.filter((instance) => instance.api_enabled !== false);
  return apiNodes.length <= 1;
};

// region leases of the sockets of this node
const renewNodeLeases = async () => {
  const sessionConnections = new Map<string, string[]>();
  nodeConnections.forEach((sessionId, connectionId) => {
    sessionConnections.set(sessionId, [...(sessionConnections.get(sessionId) ?? []), connectionId]);
  });
  await Promise.all([...sessionConnections.entries()].map(async ([sessionId, connectionIds]) => {
    try {
      const expiry = await saveSessionLeases(sessionId, connectionIds, SESSION_PRESENCE_LEASE_TTL, PRESENCE_KEYS_TTL);
      if (expiry === undefined) {
        // The session has been logged out: its sockets are no longer tracked
        connectionIds.forEach((connectionId) => nodeConnections.delete(connectionId));
        return;
      }
      await scheduleSessionCheck(sessionId, expiry + SESSION_PRESENCE_GRACE_PERIOD, 'GT');
    } catch (cause) {
      logApp.error('[SESSION PRESENCE] Error renewing the leases of a session', { cause });
    }
  }));
};

const startLeasesRenewal = () => {
  if (!renewTimer) {
    renewTimer = setInterval(() => {
      if (!getStoppingState()) {
        renewNodeLeases().catch((cause) => logApp.error('[SESSION PRESENCE] Error renewing the leases', { cause }));
      }
    }, LEASE_RENEW_INTERVAL);
    renewTimer.unref();
  }
};

// Returns the id of the registered connection, or undefined when the session is being logged out
export const registerSessionPresence = async (sessionId: string, origin: PresenceOrigin) => {
  const connectionId = uuidv4();
  const expiry = await saveSessionLeases(sessionId, [connectionId], SESSION_PRESENCE_LEASE_TTL, PRESENCE_KEYS_TTL, origin);
  if (expiry === undefined) {
    return undefined;
  }
  nodeConnections.set(connectionId, sessionId);
  startLeasesRenewal();
  // A session is always scheduled while it has leases: if this node crashes, the check still happens
  await scheduleSessionCheck(sessionId, expiry + SESSION_PRESENCE_GRACE_PERIOD, 'GT');
  return connectionId;
};

export const unregisterSessionPresence = async (sessionId: string, connectionId: string) => {
  if (!nodeConnections.delete(connectionId)) {
    return;
  }
  // Sockets closed by the platform shutdown are not tabs closed by the user: their leases expire,
  // which leaves the time for the tabs to reconnect to another node
  if (getStoppingState()) {
    return;
  }
  const { liveLeases, now } = await removeSessionLease(sessionId, connectionId);
  if (liveLeases === 0) {
    await scheduleSessionCheck(sessionId, now + SESSION_PRESENCE_GRACE_PERIOD, 'LT');
  }
};
// endregion
