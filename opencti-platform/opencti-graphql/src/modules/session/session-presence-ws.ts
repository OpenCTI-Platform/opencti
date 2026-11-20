import { promisify } from 'node:util';
import type { Context } from 'graphql-ws';
import type { Extra } from 'graphql-ws/use/ws';
import { isFeatureEnabled, logApp, SESSION_PRESENCE_FEATURE_FLAG } from '../../config/conf';
import { getSessionMiddleware } from '../../database/session';
import { userWithOrigin } from '../user/user-domain';
import { registerSessionPresence, unregisterSessionPresence } from './session-presence-domain';
import type { PresenceConnection, SessionRequest } from './session-presence-types';

const socketConnections = new WeakMap<object, PresenceConnection>();

// graphql-ws hooks, the presence must never prevent the socket from being used.
// Nothing is tracked without the SESSION_PRESENCE feature flag. With it, every node tracks its sockets in memory,
// and writes their leases to Redis only while the platform setting is on (see session-presence-domain).
export const onSessionPresenceConnect = async (ctx: Context<Record<string, unknown> | undefined, Extra>) => {
  if (!isFeatureEnabled(SESSION_PRESENCE_FEATURE_FLAG)) {
    return;
  }
  try {
    const { socket } = ctx.extra;
    const request = ctx.extra.request as SessionRequest;
    // The session is read once per socket: the session middleware skips a request already holding a session,
    // so the subscriptions of this socket (extractWsSessionContext) reuse it.
    const session = await getSessionMiddleware();
    await promisify(session)(request, {});
    const user = request.session?.user;
    // The socket may have been closed while the session was parsed
    if (!user || !request.sessionID || socket.readyState !== socket.OPEN) {
      return;
    }
    // Same origin as an explicit logout, so both logout events are consistent in the audit
    const { origin } = userWithOrigin(request, user);
    const connectionId = await registerSessionPresence(request.sessionID, origin);
    // Refused while the session is being logged out
    if (!connectionId) {
      return;
    }
    const connection = { sessionId: request.sessionID, connectionId };
    // The socket may have been closed while it was registered: its close hook found nothing to unregister
    if (socket.readyState !== socket.OPEN) {
      await unregisterSessionPresence(connection.sessionId, connection.connectionId);
      return;
    }
    socketConnections.set(socket, connection);
  } catch (cause) {
    logApp.error('[SESSION PRESENCE] Error registering a session connection', { cause });
  }
};

export const onSessionPresenceClose = async (ctx: Context<Record<string, unknown> | undefined, Extra>) => {
  const connection = socketConnections.get(ctx.extra.socket);
  if (connection) {
    socketConnections.delete(ctx.extra.socket);
    try {
      await unregisterSessionPresence(connection.sessionId, connection.connectionId);
    } catch (cause) {
      logApp.error('[SESSION PRESENCE] Error unregistering a session connection', { cause });
    }
  }
};
