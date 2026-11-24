import { v4 as uuidv4 } from 'uuid';
import conf, { getStoppingState, isFeatureEnabled, logApp, SESSION_PRESENCE_FEATURE_FLAG } from '../../config/conf';
import { findSessionByRawId, killSessionByRawId } from '../../database/session';
import { getEntityFromCache } from '../../database/cache';
import { getClusterInstances } from '../../database/redis';
import { isModuleActivated } from '../../database/cluster-module';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import { meterManager } from '../../config/tracing';
import type { BasicStoreSettings } from '../../types/settings';
import type { PresenceOrigin } from './session-presence-types';
import {
  checkSessionLeases,
  findDueSessions,
  findSessionOrigin,
  releaseSessionPresence,
  removeSessionLease,
  saveSessionLeases,
  scheduleSessionCheck,
} from './session-presence-store';

// Logout a session once its last browser tab is gone.
// Every authenticated tab keeps a GraphQL WebSocket open for its whole life (root `me` subscription),
// so the session is considered abandoned when none of its sockets is alive for the grace period.
// Each socket holds a lease in Redis, renewed by its node: the presence is shared by all the nodes,
// and the leases of a crashed node expire. The session presence manager then logs out the abandoned sessions.
// Every node tracks its sockets in memory, but only writes their leases to Redis while the setting is on:
// the renewal following its activation covers the tabs already open. It runs well within the grace period,
// so a tab closed meanwhile cannot logout a session whose other tabs have no lease yet.

const SESSION_PRESENCE_GRACE_PERIOD: number = conf.get('app:session_presence:grace_period') ?? 30000;
const SESSION_PRESENCE_LEASE_TTL: number = conf.get('app:session_presence:lease_ttl') ?? 30000;
const LEASE_RENEW_INTERVAL = Math.floor(SESSION_PRESENCE_LEASE_TTL / 3);
// The origin and the deadline of a session are kept until its logout: after its last lease, the grace period and the time to sweep it
const PRESENCE_KEYS_TTL = SESSION_PRESENCE_LEASE_TTL + SESSION_PRESENCE_GRACE_PERIOD + 10 * 60 * 1000;
// Long enough for every node to drop its sockets of a logged out session, at their next renewal
const CLOSING_TTL = 6 * LEASE_RENEW_INTERVAL;
const SWEEP_BATCH_SIZE = 100;

// Sessions held in the memory of each node can only be logged out by that node
export const IS_SHARED_SESSION_STORE = conf.get('app:session_manager') === 'shared';

// The sockets of this node, by connection id
const nodeConnections = new Map<string, { sessionId: string; origin: PresenceOrigin }>();
let renewTimer: NodeJS.Timeout | undefined;
let isMultiNodeWarned = false;

const isSessionPresenceEnabled = async () => {
  if (!isFeatureEnabled(SESSION_PRESENCE_FEATURE_FLAG)) {
    return false;
  }
  const context = executionContext('session_presence');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return settings.platform_session_presence_enabled === true;
};

// With the shared session store (default), any node can logout any session.
// With sessions held in memory, only a single node serving the API is supported. Only the nodes serving the API
// hold WebSockets: manager-only nodes are not counted, a node of a previous version doesn't tell so it is counted.
export const isSessionPresenceSupported = async () => {
  if (IS_SHARED_SESSION_STORE) {
    return true;
  }
  const instances = await getClusterInstances();
  const apiNodes = instances.filter((instance) => instance.api_enabled !== false);
  return apiNodes.length <= 1;
};

export const SESSION_PRESENCE_MANAGER_ID = 'SESSION_PRESENCE_MANAGER';

// The abandoned sessions are only logged out by the session presence manager, which can be disabled on each node
export const isSessionPresenceManagerEnabled = () => isModuleActivated(SESSION_PRESENCE_MANAGER_ID);

const isLogoutSupported = async () => {
  const isSupported = await isSessionPresenceSupported();
  if (!isSupported && !isMultiNodeWarned) {
    isMultiNodeWarned = true;
    logApp.warn('[SESSION PRESENCE] Logout when the last tab is closed needs the shared session store when several nodes serve the API, no session is logged out');
  }
  return isSupported;
};

// region leases of the sockets of this node
const renewNodeLeases = async () => {
  if (!(await isSessionPresenceEnabled())) {
    return;
  }
  const sessionConnections = new Map<string, { connectionIds: string[]; origin: PresenceOrigin }>();
  nodeConnections.forEach(({ sessionId, origin }, connectionId) => {
    const connections = sessionConnections.get(sessionId) ?? { connectionIds: [], origin };
    connections.connectionIds.push(connectionId);
    sessionConnections.set(sessionId, connections);
  });
  await Promise.all([...sessionConnections.entries()].map(async ([sessionId, { connectionIds, origin }]) => {
    try {
      // The origin is written again, for the tabs opened while the setting was off
      const checkAt = await saveSessionLeases(sessionId, connectionIds, SESSION_PRESENCE_LEASE_TTL, PRESENCE_KEYS_TTL, SESSION_PRESENCE_GRACE_PERIOD, origin);
      if (checkAt === undefined) {
        // The session has been logged out: its sockets are no longer tracked
        connectionIds.forEach((connectionId) => nodeConnections.delete(connectionId));
        meterManager.sessionPresenceConnections(nodeConnections.size);
        return;
      }
      await scheduleSessionCheck(sessionId, checkAt, 'GT');
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

// Returns the id of the registered connection, or undefined when the session is being logged out.
// The connection is tracked before its lease is written: if Redis fails, the next renewal writes its lease
// and schedules its session. If this node crashes meanwhile, the socket is closed, so the tab reconnects to another node.
export const registerSessionPresence = async (sessionId: string, origin: PresenceOrigin) => {
  const connectionId = uuidv4();
  nodeConnections.set(connectionId, { sessionId, origin });
  meterManager.sessionPresenceConnections(nodeConnections.size);
  startLeasesRenewal();
  try {
    if (await isSessionPresenceEnabled()) {
      const checkAt = await saveSessionLeases(sessionId, [connectionId], SESSION_PRESENCE_LEASE_TTL, PRESENCE_KEYS_TTL, SESSION_PRESENCE_GRACE_PERIOD, origin);
      if (checkAt === undefined) {
        nodeConnections.delete(connectionId);
        meterManager.sessionPresenceConnections(nodeConnections.size);
        return undefined;
      }
      // A session is always scheduled while it has leases: if this node crashes, the check still happens
      await scheduleSessionCheck(sessionId, checkAt, 'GT');
    }
  } catch (cause) {
    logApp.error('[SESSION PRESENCE] Error registering a connection, its lease is written at the next renewal', { cause });
  }
  return connectionId;
};

export const unregisterSessionPresence = async (sessionId: string, connectionId: string) => {
  if (!nodeConnections.delete(connectionId)) {
    return;
  }
  meterManager.sessionPresenceConnections(nodeConnections.size);
  // Sockets closed by the platform shutdown are not tabs closed by the user: their leases expire,
  // which leaves the time for the tabs to reconnect to another node
  if (getStoppingState() || !(await isSessionPresenceEnabled())) {
    return;
  }
  const { liveLeases, checkAt } = await removeSessionLease(sessionId, connectionId, PRESENCE_KEYS_TTL, SESSION_PRESENCE_GRACE_PERIOD);
  if (liveLeases === 0) {
    meterManager.sessionPresenceLastDisconnection();
    await scheduleSessionCheck(sessionId, checkAt, 'LT');
  }
};
// endregion

// region logout of the abandoned sessions, run by the session presence manager
const checkDueSession = async (sessionId: string, canLogout: boolean) => {
  // Without logout, the session is not marked as closing: its tabs can register again right away
  // The session may have been listed before a tab came back: it is kept until its own deadline
  const { isAlive, time } = await checkSessionLeases(sessionId, canLogout ? CLOSING_TTL : 0, SESSION_PRESENCE_GRACE_PERIOD);
  if (isAlive) {
    meterManager.sessionPresenceCheck('alive');
    await scheduleSessionCheck(sessionId, time, 'GT');
    return;
  }
  let isLoggedOut = false;
  if (canLogout) {
    const session = await findSessionByRawId(sessionId);
    // A session already logged out or expired is only released
    if (session?.user) {
      // The origin expires with the other keys of the session: a later check, for instance once the manager is enabled
      // again, is audited as an internal action of the user (the activity listener drops an action without origin)
      const origin = await findSessionOrigin(sessionId) ?? { socket: 'internal', user_id: session.user.id };
      await killSessionByRawId(sessionId);
      await publishUserAction({
        user: { ...session.user, origin },
        event_type: 'authentication',
        event_access: 'administration',
        event_scope: 'logout',
        context_data: { reason: 'last_tab_closed' },
      });
      isLoggedOut = true;
    }
  }
  // Released only once logged out: if this node stops before, another one checks the session again
  await releaseSessionPresence(sessionId);
  meterManager.sessionPresenceCheck(isLoggedOut ? 'logout' : 'released');
};

export const logoutAbandonedSessions = async () => {
  const canLogout = (await isSessionPresenceEnabled()) && (await isLogoutSupported());
  const dueSessions = await findDueSessions(SWEEP_BATCH_SIZE);
  for (let index = 0; index < dueSessions.length; index += 1) {
    try {
      await checkDueSession(dueSessions[index], canLogout);
    } catch (cause) {
      logApp.error('[SESSION PRESENCE] Error logging out an abandoned session', { cause });
    }
  }
};
// endregion
