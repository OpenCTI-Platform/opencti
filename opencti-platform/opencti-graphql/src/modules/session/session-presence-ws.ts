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
// Nothing is tracked without the SESSION_PRESENCE feature flag. With it, connections are tracked even when
// the platform setting is off: the setting is only read before a logout, so enabling it also covers the tabs already open.
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
