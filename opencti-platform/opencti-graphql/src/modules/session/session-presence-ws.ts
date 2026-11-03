import { promisify } from 'node:util';
import type { Context } from 'graphql-ws';
import type { Extra } from 'graphql-ws/use/ws';
import { logApp } from '../../config/conf';
import { getSessionMiddleware } from '../../database/session';
import { hashSHA256 } from '../../utils/hash';
import { registerSessionPresence, unregisterSessionPresence } from './session-presence-domain';
import type { PresenceConnection, PresenceOrigin, SessionRequest } from './session-presence-types';

const socketConnections = new WeakMap<object, PresenceConnection>();

// graphql-ws hooks, the presence must never prevent the socket from being used.
// Connections are tracked even when the feature is disabled: the setting is only read before a logout,
// so enabling it also covers the tabs already open.
export const onSessionPresenceConnect = async (ctx: Context<Record<string, unknown> | undefined, Extra>) => {
  try {
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
