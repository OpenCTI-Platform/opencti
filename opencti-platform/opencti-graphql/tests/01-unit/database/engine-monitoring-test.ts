import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// The monitor only sees the engine through these three exports, so the test drives them directly.
const { state } = vi.hoisted(() => ({ state: { isElk: true, engine: null as any } }));

vi.mock('../../../src/database/engine', () => ({
  get engine() {
    return state.engine;
  },
  isElkEngine: () => state.isElk,
  oebp: (result: any) => (state.isElk ? result : result.body),
}));
vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/config/conf')>()),
  isFeatureEnabled: vi.fn(() => true),
}));

import { logApp } from '../../../src/config/conf';
import { startEngineHealthMonitor, stopEngineHealthMonitor } from '../../../src/database/engine-monitoring';

const ONE_MINUTE = 60_000;

// Elasticsearch answers with the bare response, OpenSearch wraps it in a body envelope
const fakeEngine = (wrap: (response: any) => any) => ({
  cluster: { health: vi.fn(async () => wrap({ status: 'green', number_of_nodes: 3 })) },
  nodes: { stats: vi.fn(async () => wrap({ nodes: { n1: { name: 'node-1', jvm: { mem: { heap_used_in_bytes: 50, heap_max_in_bytes: 100 } } } } })) },
  cat: { threadPool: vi.fn(async () => wrap([{ node_name: 'node-1', name: 'search', active: '1', queue: '0', rejected: '0', completed: '10' }])) },
});

const runOneMonitorCycle = async () => {
  startEngineHealthMonitor();
  await vi.advanceTimersByTimeAsync(ONE_MINUTE);
};

describe('engine: health monitor', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    stopEngineHealthMonitor();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('should query Elasticsearch with array parameters and read the bare responses', async () => {
    state.isElk = true;
    state.engine = fakeEngine((response) => response);
    const info = vi.spyOn(logApp, 'info');

    await runOneMonitorCycle();

    expect(state.engine.nodes.stats).toHaveBeenCalledWith({ metric: ['jvm', 'os', 'process'] });
    expect(state.engine.cat.threadPool).toHaveBeenCalledWith({ format: 'json', h: 'node_name,name,active,queue,rejected,completed' });
    expect(info).toHaveBeenCalledWith('[SEARCH] Cluster health', expect.objectContaining({ status: 'green', numberOfNodes: 3 }));
    expect(info).toHaveBeenCalledWith('[SEARCH] Node stats', expect.objectContaining({ nodeName: 'node-1', jvmHeapUsedPercent: 50 }));
    expect(info).toHaveBeenCalledWith('[SEARCH] Thread pool stats', expect.objectContaining({ pool: 'search', active: 1 }));
  });

  it('should query OpenSearch with string parameters and read the body envelope', async () => {
    state.isElk = false;
    state.engine = fakeEngine((response) => ({ body: response }));
    const info = vi.spyOn(logApp, 'info');

    await runOneMonitorCycle();

    expect(state.engine.nodes.stats).toHaveBeenCalledWith({ metric: 'jvm,os,process' });
    expect(state.engine.cat.threadPool).toHaveBeenCalledWith({ format: 'json', h: ['node_name', 'name', 'active', 'queue', 'rejected', 'completed'] });
    expect(info).toHaveBeenCalledWith('[SEARCH] Cluster health', expect.objectContaining({ status: 'green', numberOfNodes: 3 }));
    expect(info).toHaveBeenCalledWith('[SEARCH] Node stats', expect.objectContaining({ nodeName: 'node-1', jvmHeapUsedPercent: 50 }));
  });
});
