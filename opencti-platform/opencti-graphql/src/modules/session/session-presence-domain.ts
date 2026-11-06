import { v4 as uuidv4 } from 'uuid';
import conf, { getStoppingState, logApp } from '../../config/conf';
import { findSessionByRawId, killSessionByRawId } from '../../database/session';
import { getEntityFromCache } from '../../database/cache';
import { getClusterInstances } from '../../database/redis';
import { ENTITY_TYPE_SETTINGS } from '../../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { publishUserAction } from '../../listener/UserActionListener';
import type { BasicStoreSettings } from '../../types/settings';
import type { PresenceOrigin } from './session-presence-types';

// Logout a session once its last browser tab is gone.
// Every authenticated tab keeps a GraphQL WebSocket open for its whole life (root `me` subscription),
// so the session is considered abandoned when its last socket closes and none reopens within the grace period.
// Dead sockets (crash, power or network loss) are closed by the ws keepalive, so they end up here too.
// /!\ Presence is held in the memory of the node owning the socket: a node cannot see the sockets of another node,
// so no session is logged out while several platform nodes are running.

const SESSION_PRESENCE_GRACE_PERIOD: number = conf.get('app:session_presence:grace_period') ?? 30000;

// session id -> connection id -> origin of the connection
const sessionConnections = new Map<string, Map<string, PresenceOrigin>>();
const pendingLogouts = new Map<string, NodeJS.Timeout>();
let isMultiNodeWarned = false;

const isSessionPresenceEnabled = async () => {
  const context = executionContext('session_presence');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return settings.platform_session_presence_enabled === true;
};

// A node restarted in place stays listed until its registration expires, pausing the feature meanwhile
const isSingleNodePlatform = async () => {
  const instances = await getClusterInstances();
  if (instances.length > 1 && !isMultiNodeWarned) {
    isMultiNodeWarned = true;
    logApp.warn('[SESSION PRESENCE] Logout when the last tab is closed is not supported on a multi-node platform, no session is logged out', { nodes: instances.length });
  }
  return instances.length <= 1;
};

const logoutAbandonedSession = async (sessionId: string, origin: PresenceOrigin) => {
  pendingLogouts.delete(sessionId);
  // A stopping node no longer knows the sockets that reconnected elsewhere
  if (getStoppingState() || sessionConnections.has(sessionId) || !(await isSessionPresenceEnabled())) {
    return;
  }
  if (!(await isSingleNodePlatform())) {
    return;
  }
  const session = await findSessionByRawId(sessionId);
  // While the checks above were awaited, a tab may have reconnected (it is still open),
  // or reconnected and closed again (a newer logout is pending, with its own grace period)
  if (!session?.user || sessionConnections.has(sessionId) || pendingLogouts.has(sessionId)) {
    return;
  }
  await killSessionByRawId(sessionId);
  await publishUserAction({
    user: { ...session.user, origin },
    event_type: 'authentication',
    event_access: 'administration',
    event_scope: 'logout',
    context_data: { reason: 'last_tab_closed' },
  });
};

export const registerSessionPresence = (sessionId: string, origin: PresenceOrigin) => {
  const pendingLogout = pendingLogouts.get(sessionId);
  if (pendingLogout) {
    clearTimeout(pendingLogout);
    pendingLogouts.delete(sessionId);
  }
  const connectionId = uuidv4();
  const connections = sessionConnections.get(sessionId) ?? new Map<string, PresenceOrigin>();
  connections.set(connectionId, origin);
  sessionConnections.set(sessionId, connections);
  return connectionId;
};

export const unregisterSessionPresence = (sessionId: string, connectionId: string) => {
  const connections = sessionConnections.get(sessionId);
  const origin = connections?.get(connectionId);
  if (!connections || !origin) {
    return;
  }
  connections.delete(connectionId);
  if (connections.size > 0) {
    return;
  }
  sessionConnections.delete(sessionId);
  // Sockets closed by the platform shutdown are not tabs closed by the user
  if (getStoppingState()) {
    return;
  }
  const pendingLogout = setTimeout(() => {
    logoutAbandonedSession(sessionId, origin).catch((cause) => {
      logApp.error('[SESSION PRESENCE] Error logging out an abandoned session', { cause });
    });
  }, SESSION_PRESENCE_GRACE_PERIOD);
  pendingLogouts.set(sessionId, pendingLogout);
};
