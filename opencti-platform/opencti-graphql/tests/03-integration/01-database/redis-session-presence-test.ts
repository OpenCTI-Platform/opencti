import { afterEach, describe, expect, it } from 'vitest';
import {
  checkSessionLeases,
  findDueSessions,
  findSessionOrigin,
  releaseSessionPresence,
  removeSessionLease,
  saveSessionLeases,
  scheduleSessionCheck,
} from '../../../src/modules/session/session-presence-store';

const KEYS_TTL = 60000;
const GRACE = 30000;
const ORIGIN = { socket: 'query', ip: '10.0.0.1', user_id: 'user-id' };

const wait = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});

// Each test works on its own session, released at the end so the due list stays clean
const sessionIds: string[] = [];
const newSessionId = () => {
  const sessionId = `presence-test-${Date.now()}-${Math.floor(Math.random() * 100000)}`;
  sessionIds.push(sessionId);
  return sessionId;
};

describe('Redis session presence', () => {
  afterEach(async () => {
    await Promise.all(sessionIds.splice(0).map((sessionId) => releaseSessionPresence(sessionId)));
  });

  it('should keep a session until the end of the grace period following its last lease', async () => {
    const sessionId = newSessionId();
    const firstCheckAt = await saveSessionLeases(sessionId, ['connection-1'], 60000, KEYS_TTL, GRACE, ORIGIN) as number;
    const secondCheckAt = await saveSessionLeases(sessionId, ['connection-2'], 120000, KEYS_TTL, GRACE);
    expect(secondCheckAt).toBeGreaterThan(firstCheckAt);
    // A shorter lease cannot bring the deadline back
    expect(await saveSessionLeases(sessionId, ['connection-3'], 60000, KEYS_TTL, GRACE)).toEqual(secondCheckAt);

    expect(await removeSessionLease(sessionId, 'connection-2', KEYS_TTL, GRACE)).toEqual({ liveLeases: 2, checkAt: 0 });
    expect(await checkSessionLeases(sessionId, 1000, GRACE)).toEqual({ isAlive: true, time: secondCheckAt });
    // The origin of the first connection is kept by the leases written without one
    expect(await findSessionOrigin(sessionId)).toEqual(ORIGIN);
  });

  it('should count expired leases as gone, and start the grace period with the last disconnection', async () => {
    const sessionId = newSessionId();
    await saveSessionLeases(sessionId, ['connection-1'], 50, KEYS_TTL, 0);
    await saveSessionLeases(sessionId, ['connection-2'], 60000, KEYS_TTL, 0);
    await wait(100);

    const { liveLeases, checkAt } = await removeSessionLease(sessionId, 'connection-2', KEYS_TTL, 60000);
    expect(liveLeases).toEqual(0);
    expect(await checkSessionLeases(sessionId, 1000, 60000)).toEqual({ isAlive: true, time: checkAt });
  });

  it('should keep a session listed before a tab came back and closed', async () => {
    const sessionId = newSessionId();
    await saveSessionLeases(sessionId, ['connection-1'], 60000, KEYS_TTL, 100);
    const { checkAt: firstCheckAt } = await removeSessionLease(sessionId, 'connection-1', KEYS_TTL, 100);
    await scheduleSessionCheck(sessionId, firstCheckAt, 'LT');
    await wait(150);
    expect(await findDueSessions(10000)).toContain(sessionId);

    // A tab comes back and closes: its grace period starts again, whatever the time the session was listed for
    await saveSessionLeases(sessionId, ['connection-2'], 60000, KEYS_TTL, 100);
    const { checkAt: secondCheckAt } = await removeSessionLease(sessionId, 'connection-2', KEYS_TTL, 100);
    expect(secondCheckAt).toBeGreaterThan(firstCheckAt);
    expect(await checkSessionLeases(sessionId, 1000, 100)).toEqual({ isAlive: true, time: secondCheckAt });

    await wait(150);
    expect((await checkSessionLeases(sessionId, 1000, 100)).isAlive).toBe(false);
  });

  it('should refuse new leases while the session is being logged out', async () => {
    const sessionId = newSessionId();
    await saveSessionLeases(sessionId, ['connection-1'], 50, KEYS_TTL, 0);
    await wait(100);

    const check = await checkSessionLeases(sessionId, 200, 0);
    expect(check.isAlive).toBe(false);
    expect(await saveSessionLeases(sessionId, ['connection-2'], 60000, KEYS_TTL, 0)).toBeUndefined();
    // The leases are dropped with the check: the refused connection was not added
    expect((await checkSessionLeases(sessionId, 200, 0)).isAlive).toBe(false);

    await wait(250);
    expect(await saveSessionLeases(sessionId, ['connection-2'], 60000, KEYS_TTL, 0)).toBeDefined();
  });

  it('should not mark a session released without logout as closing', async () => {
    const sessionId = newSessionId();
    expect((await checkSessionLeases(sessionId, 0, 0)).isAlive).toBe(false);
    expect(await saveSessionLeases(sessionId, ['connection-1'], 60000, KEYS_TTL, 0)).toBeDefined();
  });

  it('should only push a check forward on renewal and bring it forward on the last disconnection', async () => {
    const sessionId = newSessionId();
    const past = Date.now() - 60000;
    await scheduleSessionCheck(sessionId, past, 'GT');
    expect(await findDueSessions(10000)).toContain(sessionId);

    // A renewal pushes it to the future, an older renewal cannot bring it back
    await scheduleSessionCheck(sessionId, past + 120000, 'GT');
    await scheduleSessionCheck(sessionId, past, 'GT');
    expect(await findDueSessions(10000)).not.toContain(sessionId);

    // The last disconnection brings it forward, a later one cannot push it back
    await scheduleSessionCheck(sessionId, past, 'LT');
    await scheduleSessionCheck(sessionId, past + 120000, 'LT');
    expect(await findDueSessions(10000)).toContain(sessionId);
  });

  it('should release a session with its origin', async () => {
    const sessionId = newSessionId();
    await saveSessionLeases(sessionId, ['connection-1'], 60000, KEYS_TTL, GRACE, ORIGIN);
    await scheduleSessionCheck(sessionId, Date.now() - 1000, 'LT');

    await releaseSessionPresence(sessionId);
    expect(await findSessionOrigin(sessionId)).toBeUndefined();
    expect(await findDueSessions(10000)).not.toContain(sessionId);
  });
});
