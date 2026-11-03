import type { IncomingMessage } from 'node:http';
import type { AuthUser, UserOrigin } from '../../types/user';

export type PresenceOrigin = Partial<UserOrigin> & { ip?: string };

export interface PresenceConnection {
  sessionId: string;
  connectionId: string;
}

// WebSocket upgrade request, once parsed by the session middleware
export type SessionRequest = IncomingMessage & {
  sessionID?: string;
  session?: { user?: AuthUser };
};
