import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { onSessionPresenceClose, onSessionPresenceConnect, registerSessionPresence, unregisterSessionPresence } from '../../../src/http/sessionPresence';
import * as cache from '../../../src/database/cache';
import * as session from '../../../src/database/session';
import * as listener from '../../../src/listener/UserActionListener';
import { getStoppingState } from '../../../src/config/conf';

const GRACE_PERIOD = vi.hoisted(() => 30000);

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
}));

vi.mock('../../../src/database/session', () => ({
  findSessionByRawId: vi.fn(),
  killSessionByRawId: vi.fn(),
  getSessionMiddleware: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal: any) => {
  const actual = await importOriginal();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: vi.fn((key) => {
        if (key === 'app:session_presence:grace_period') return GRACE_PERIOD;
        return actual.default.get(key);
      }),
    },
    getStoppingState: vi.fn(() => false),
    logApp: { ...actual.logApp, error: vi.fn() },
  };
});

vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn().mockReturnValue('mock-context'),
  SYSTEM_USER: { id: 'system-user' },
}));

const USER = { id: 'user-id', groups: [{ internal_id: 'group-id' }], organizations: [] };
const ORIGIN = { socket: 'query', user_id: USER.id };

// Presence state is module wide: every test works on its own session id
let sessionCounter = 0;
const nextSessionId = () => {
  sessionCounter += 1;
  return `session-${sessionCounter}`;
};

const enablePresence = (enabled: boolean) => {
  vi.mocked(cache.getEntityFromCache).mockResolvedValue({ platform_session_presence_enabled: enabled } as any);
};

const storeSession = (sessionData: unknown) => {
  vi.mocked(session.findSessionByRawId).mockResolvedValue(sessionData);
};

describe('session presence', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    vi.mocked(getStoppingState).mockReturnValue(false);
    enablePresence(true);
    storeSession({ user: USER });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should logout the session after the grace period once its last connection is closed', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD - 1);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(session.findSessionByRawId).toHaveBeenCalledWith(sessionId);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
    expect(listener.publishUserAction).toHaveBeenCalledExactlyOnceWith({
      user: { ...USER, origin: ORIGIN },
      event_type: 'authentication',
      event_access: 'administration',
      event_scope: 'logout',
      context_data: { reason: 'last_tab_closed' },
    });
  });

  it('should keep the session while another connection is alive', async () => {
    const sessionId = nextSessionId();
    const firstConnectionId = registerSessionPresence(sessionId, ORIGIN);
    registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, firstConnectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD * 2);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should cancel the logout when a connection reopens within the grace period', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);
    await vi.advanceTimersByTimeAsync(GRACE_PERIOD / 2);
    registerSessionPresence(sessionId, ORIGIN);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD * 2);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should only logout the session that lost its connections', async () => {
    const closedSessionId = nextSessionId();
    const openSessionId = nextSessionId();
    const connectionId = registerSessionPresence(closedSessionId, ORIGIN);
    registerSessionPresence(openSessionId, ORIGIN);
    unregisterSessionPresence(closedSessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(closedSessionId);
  });

  it('should ignore an unknown or already closed connection', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);
    unregisterSessionPresence(sessionId, connectionId);
    unregisterSessionPresence(nextSessionId(), 'unknown-connection');

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD * 2);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should not logout when the feature is disabled during the grace period', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);
    enablePresence(false);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();
  });

  it('should not logout sessions whose sockets are closed by the platform shutdown', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    vi.mocked(getStoppingState).mockReturnValue(true);
    unregisterSessionPresence(sessionId, connectionId);
    vi.mocked(getStoppingState).mockReturnValue(false);

    // Even if the platform finally keeps running, nothing was scheduled
    await vi.advanceTimersByTimeAsync(GRACE_PERIOD * 2);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
  });

  it('should not logout when the platform is stopping at the end of the grace period', async () => {
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);
    vi.mocked(getStoppingState).mockReturnValue(true);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();
  });

  it('should not publish a logout for a session already logged out or expired', async () => {
    storeSession(null);
    const sessionId = nextSessionId();
    const connectionId = registerSessionPresence(sessionId, ORIGIN);
    unregisterSessionPresence(sessionId, connectionId);

    await vi.advanceTimersByTimeAsync(GRACE_PERIOD);
    expect(session.killSessionByRawId).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();
  });

  describe('graphql-ws hooks', () => {
    const OPEN = 1;
    const CLOSED = 3;

    const mockSessionMiddleware = (sessionId: string, sessionData: unknown) => {
      const middleware = (req: any, _res: unknown, next: () => void) => {
        req.sessionID = sessionId;
        req.session = sessionData;
        next();
      };
      vi.mocked(session.getSessionMiddleware).mockResolvedValue(middleware as any);
    };

    const buildContext = (readyState = OPEN) => {
      const socket = { readyState, OPEN };
      const request = { socket: { remoteAddress: '10.0.0.1' } };
      return { extra: { socket, request } } as any;
    };

    it('should track an authenticated socket until it closes', async () => {
      const sessionId = nextSessionId();
      mockSessionMiddleware(sessionId, { user: USER });
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      onSessionPresenceClose(ctx);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.killSessionByRawId).toHaveBeenCalledExactlyOnceWith(sessionId);
      const { user } = vi.mocked(listener.publishUserAction).mock.calls[0][0];
      expect(user.origin).toMatchObject({
        socket: 'query',
        ip: '10.0.0.1',
        user_id: USER.id,
        group_ids: ['group-id'],
        organization_ids: [],
      });
    });

    it('should not track sockets when the feature is disabled', async () => {
      enablePresence(false);
      mockSessionMiddleware(nextSessionId(), { user: USER });
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      onSessionPresenceClose(ctx);
      enablePresence(true);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.getSessionMiddleware).not.toHaveBeenCalled();
      expect(session.killSessionByRawId).not.toHaveBeenCalled();
    });

    it('should not track an unauthenticated socket', async () => {
      mockSessionMiddleware(nextSessionId(), {});
      const ctx = buildContext();

      await onSessionPresenceConnect(ctx);
      onSessionPresenceClose(ctx);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.killSessionByRawId).not.toHaveBeenCalled();
    });

    it('should not track a socket closed while its session was parsed', async () => {
      mockSessionMiddleware(nextSessionId(), { user: USER });
      const ctx = buildContext(CLOSED);

      await onSessionPresenceConnect(ctx);
      onSessionPresenceClose(ctx);
      await vi.advanceTimersByTimeAsync(GRACE_PERIOD);

      expect(session.killSessionByRawId).not.toHaveBeenCalled();
    });

    it('should accept the socket even if the presence fails', async () => {
      vi.mocked(session.getSessionMiddleware).mockRejectedValue(new Error('store unavailable'));

      await expect(onSessionPresenceConnect(buildContext())).resolves.toBeUndefined();
    });
  });
});
