import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { platformStart } from '../../src/boot';
import { logApp } from '../../src/config/conf';
import * as bootUtils from '../../src/boot-utils';

vi.mock('../../src/boot-utils', () => ({
  checkSystemDependencies: vi.fn(),
}));
vi.mock('../../src/http/httpLiveness', () => ({
  startLivenessServer: vi.fn(),
  stopLivenessServer: vi.fn(),
}));
vi.mock('../../src/initialization', () => ({
  default: vi.fn(),
  checkFeatureFlags: vi.fn(),
}));
vi.mock('../../src/manager/cacheManager', () => ({
  default: {
    start: vi.fn(),
    shutdown: vi.fn(),
  },
}));
vi.mock('../../src/managers', () => ({
  startModules: vi.fn(),
  shutdownModules: vi.fn(),
}));
vi.mock('../../src/lock/master-lock', () => ({
  initLockFork: vi.fn(),
}));
vi.mock('../../src/database/engine-monitoring', () => ({
  startEngineHealthMonitor: vi.fn(),
  stopEngineHealthMonitor: vi.fn(),
}));
vi.mock('../../src/database/redis', () => ({
  shutdownRedisClients: vi.fn(),
}));

describe('Build commit startup warning', () => {
  beforeEach(() => {
    vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`Unexpected process.exit(${code})`);
    });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it('should warn once when build metadata is absent', async () => {
    vi.stubEnv('BUILD_COMMIT', '');
    vi.mocked(bootUtils.checkSystemDependencies).mockResolvedValue(true);
    const warningSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => logApp);

    await platformStart();

    expect(warningSpy).toHaveBeenCalledOnce();
    expect(warningSpy).toHaveBeenCalledWith('[OPENCTI] Build commit metadata is missing or invalid');
  });

  it('should warn once when build metadata is malformed', async () => {
    vi.stubEnv('BUILD_COMMIT', 'not-a-commit');
    vi.mocked(bootUtils.checkSystemDependencies).mockResolvedValue(true);
    const warningSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => logApp);

    await platformStart();

    expect(warningSpy).toHaveBeenCalledOnce();
    expect(warningSpy).toHaveBeenCalledWith('[OPENCTI] Build commit metadata is missing or invalid');
  });

  it('should not warn when build metadata contains a valid commit', async () => {
    vi.stubEnv('BUILD_COMMIT', '0123456789abcdef');
    vi.mocked(bootUtils.checkSystemDependencies).mockResolvedValue(true);
    const warningSpy = vi.spyOn(logApp, 'warn').mockImplementation(() => logApp);

    await platformStart();

    expect(warningSpy).not.toHaveBeenCalled();
  });
});
