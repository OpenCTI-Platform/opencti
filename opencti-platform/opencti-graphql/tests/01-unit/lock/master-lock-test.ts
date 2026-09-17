import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EventEmitter } from 'events';

class FakeForkedProcess extends EventEmitter {
  send = vi.fn();
}

describe('master-lock', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  it('should warn when receiving malformed child message', async () => {
    const fakeForkedProcess = new FakeForkedProcess();
    const warn = vi.fn();

    vi.doMock('child_process', () => ({
      fork: vi.fn(() => fakeForkedProcess),
    }));

    vi.doMock('../../../src/database/redis', () => ({
      lockResource: vi.fn(),
    }));

    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal<typeof import('../../../src/config/conf')>();
      return {
        ...actual,
        default: { get: vi.fn(() => '256') },
        booleanConf: vi.fn(() => true),
        logApp: {
          ...actual.logApp,
          info: vi.fn(),
          warn,
        },
      };
    });

    const { initLockFork } = await import('../../../src/lock/master-lock');
    initLockFork();

    fakeForkedProcess.emit('message', { type: 'lock' });

    expect(warn).toHaveBeenCalledWith(
      '[LOCKING] Ignoring malformed message from child lock process',
      {
        type: 'lock',
        keys: ['type'],
      },
    );
  });
});
