import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const { registerClusterInstance } = vi.hoisted(() => ({ registerClusterInstance: vi.fn() }));

// The managers import the python bridge, which loads python modules on import
vi.mock('../../../src/python/pythonBridge', () => ({
  execChildPython: vi.fn(),
  createStixPatternSync: vi.fn(),
  createStixPattern: vi.fn(),
  checkIndicatorSyntax: vi.fn(),
  checkPythonAvailability: vi.fn(),
}));
vi.mock('../../../src/database/redis', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, registerClusterInstance };
});
vi.mock('../../../src/database/cache', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, getEntityFromCache: vi.fn(async () => ({})) };
});

const { default: clusterManager } = await import('../../../src/manager/clusterManager');

const SCHEDULE_TIME = 30000;
const startingRegistrations = () => registerClusterInstance.mock.calls.filter(([, config]) => config.managers.length === 0).length;

describe('cluster manager: starting node registration', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    registerClusterInstance.mockClear();
  });

  afterEach(async () => {
    await clusterManager.shutdown();
    vi.useRealTimers();
  });

  it('should keep a starting node listed until the cluster manager starts', async () => {
    await clusterManager.registerStartingNode();
    expect(startingRegistrations()).toEqual(1);
    // managers taking longer to start than the 2 minutes expiry of the registration
    await vi.advanceTimersByTimeAsync(5 * SCHEDULE_TIME);
    expect(startingRegistrations()).toEqual(6);

    await clusterManager.start();
    const lastConfig = registerClusterInstance.mock.calls.at(-1)?.[1];
    expect(lastConfig.managers.length).toBeGreaterThan(0);
    await vi.advanceTimersByTimeAsync(2 * SCHEDULE_TIME);
    // the cluster manager now owns the registration: the starting entry is no longer written
    expect(startingRegistrations()).toEqual(6);
  });

  it('should stop renewing the starting registration on shutdown', async () => {
    await clusterManager.registerStartingNode();
    await clusterManager.shutdown();
    await vi.advanceTimersByTimeAsync(5 * SCHEDULE_TIME);
    expect(startingRegistrations()).toEqual(1);
  });
});
