import { promisify } from 'node:util';
import type { IncomingMessage } from 'node:http';
import type { Context } from 'graphql-ws';
import type { Extra } from 'graphql-ws/use/ws';
import { v4 as uuidv4 } from 'uuid';
import conf, { getStoppingState, logApp } from '../config/conf';
import { findSessionByRawId, getSessionMiddleware, killSessionByRawId } from '../database/session';
import { getEntityFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { publishUserAction } from '../listener/UserActionListener';
import { hashSHA256 } from '../utils/hash';
import type { BasicStoreSettings } from '../types/settings';
import type { AuthUser, UserOrigin } from '../types/user';

// Logout a session once its last browser tab is gone.
// Every authenticated tab keeps a GraphQL WebSocket open for its whole life (root `me` subscription),
// so the session is considered abandoned when its last socket closes and none reopens within the grace period.
// Dead sockets (crash, power or network loss) are closed by the ws keepalive, so they end up here too.
// /!\ Presence is held in the memory of the node owning the socket: a session whose tabs are spread
// across several platform nodes is not supported yet.

const SESSION_PRESENCE_GRACE_PERIOD: number = conf.get('app:session_presence:grace_period') ?? 30000;

type PresenceOrigin = Partial<UserOrigin> & { ip?: string };

interface PresenceConnection {
  sessionId: string;
  connectionId: string;
}

type SessionRequest = IncomingMessage & {
  sessionID?: string;
  session?: { user?: AuthUser };
};

// session id -> connection id -> origin of the connection
const sessionConnections = new Map<string, Map<string, PresenceOrigin>>();
const pendingLogouts = new Map<string, NodeJS.Timeout>();
const socketConnections = new WeakMap<object, PresenceConnection>();

const isSessionPresenceEnabled = async () => {
  const context = executionContext('session_presence');
  const settings = await getEntityFromCache<BasicStoreSettings>(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);
  return settings.platform_session_presence_enabled === true;
};

const logoutAbandonedSession = async (sessionId: string, origin: PresenceOrigin) => {
  pendingLogouts.delete(sessionId);
  // A stopping node no longer knows the sockets that reconnected elsewhere
  if (getStoppingState() || sessionConnections.has(sessionId) || !(await isSessionPresenceEnabled())) {
    return;
  }
  const session = await findSessionByRawId(sessionId);
  // A tab may have reconnected while the session was fetched
  if (!session?.user || sessionConnections.has(sessionId)) {
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

// graphql-ws hooks, the presence must never prevent the socket from being used
export const onSessionPresenceConnect = async (ctx: Context<Record<string, unknown> | undefined, Extra>) => {
  try {
    if (!(await isSessionPresenceEnabled())) {
      return;
    }
    const { socket } = ctx.extra;
    const request = ctx.extra.request as SessionRequest;
    const session = await getSessionMiddleware();
    await promisify(session)(request, {});
    const user = request.session?.user;
    // The socket may have been closed while the session was parsed
    if (!user || !request.sessionID || socket.readyState !== socket.OPEN) {
      return;
    }
    const origin: PresenceOrigin = {
      socket: 'query',
      ip: request.socket.remoteAddress,
      user_id: user.id,
      group_ids: user.groups?.map((g) => g.internal_id) ?? [],
      organization_ids: user.organizations?.map((o) => o.internal_id) ?? [],
      user_metadata: { sessionHash: hashSHA256(request.sessionID) },
    };
    const connectionId = registerSessionPresence(request.sessionID, origin);
    socketConnections.set(socket, { sessionId: request.sessionID, connectionId });
  } catch (cause) {
    logApp.error('[SESSION PRESENCE] Error registering a session connection', { cause });
  }
};

export const onSessionPresenceClose = (ctx: Context<Record<string, unknown> | undefined, Extra>) => {
  const connection = socketConnections.get(ctx.extra.socket);
  if (connection) {
    socketConnections.delete(ctx.extra.socket);
    unregisterSessionPresence(connection.sessionId, connection.connectionId);
  }
};
