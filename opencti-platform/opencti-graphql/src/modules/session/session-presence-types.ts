import type { Request } from 'express';
import type { AuthUser, UserOrigin } from '../../types/user';

export type PresenceOrigin = Partial<UserOrigin> & { ip?: string };

export interface PresenceConnection {
  sessionId: string;
  connectionId: string;
}

// WebSocket upgrade request, given the express request API by the http server
// and parsed by the session middleware
export type SessionRequest = Request & {
  sessionID?: string;
  session?: { user?: AuthUser };
};
