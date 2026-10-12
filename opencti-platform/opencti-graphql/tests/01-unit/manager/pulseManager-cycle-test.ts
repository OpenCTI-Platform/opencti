import { beforeEach, describe, expect, it, vi } from 'vitest';

const steps = vi.hoisted(() => ({
  runPulsePendingCleanup: vi.fn(),
  runPulseContribution: vi.fn(),
  runPulseRefresh: vi.fn(),
  runPulsePreview: vi.fn(),
  runPulseTrendingNotifications: vi.fn(),
  isPulseRefreshDeferred: vi.fn(),
  redisGetPulseState: vi.fn(),
  redisSetPulseState: vi.fn(),
}));

vi.mock('../../../src/modules/xtm/pulse/pulse-domain', () => ({
  runPulsePendingCleanup: steps.runPulsePendingCleanup,
  runPulseContribution: steps.runPulseContribution,
  runPulseRefresh: steps.runPulseRefresh,
  runPulsePreview: steps.runPulsePreview,
  isPulseRefreshDeferred: steps.isPulseRefreshDeferred,
}));
vi.mock('../../../src/modules/xtm/pulse/pulse-notifications', () => ({ runPulseTrendingNotifications: steps.runPulseTrendingNotifications }));
vi.mock('../../../src/modules/xtm/pulse/pulse-cache', () => ({ redisGetPulseState: steps.redisGetPulseState, redisSetPulseState: steps.redisSetPulseState }));

const { pulseManager } = await import('../../../src/manager/pulseManager');

describe('Threat Pulse manager cycle', () => {
  beforeEach(() => {
    Object.values(steps).forEach((step) => step.mockReset());
    steps.redisGetPulseState.mockResolvedValue({});
  });

  it('runs every step once the pending cleanup succeeded', async () => {
    await pulseManager();
    [steps.runPulseContribution, steps.runPulseRefresh, steps.runPulseTrendingNotifications, steps.runPulsePreview].forEach((step) => {
      expect(step).toHaveBeenCalledTimes(1);
    });
  });

  it('stops the cycle while the pending cleanup fails, recording why', async () => {
    steps.runPulsePendingCleanup.mockRejectedValue(new Error('Elasticsearch unavailable'));
    await pulseManager();
    expect(steps.redisSetPulseState).toHaveBeenCalledWith({ last_error: 'cleanup_failed' });
    [steps.runPulseContribution, steps.runPulseRefresh, steps.runPulseTrendingNotifications, steps.runPulsePreview].forEach((step) => {
      expect(step).not.toHaveBeenCalled();
    });
  });

  it('keeps the failure of the network refresh while it waits for the instant XTM Hub gave with its rate limit', async () => {
    const state = { last_error: 'network_refresh_failed', refresh_retry_at: '2026-10-12T13:00:00.000Z' };
    steps.redisGetPulseState.mockResolvedValue(state);
    steps.isPulseRefreshDeferred.mockReturnValue(true);
    await pulseManager();
    expect(steps.runPulseRefresh).toHaveBeenCalledTimes(1);
    expect(steps.isPulseRefreshDeferred).toHaveBeenCalledWith(state, expect.any(Number));
    expect(steps.redisSetPulseState).not.toHaveBeenCalledWith({ last_error: undefined });
  });

  it('clears the failure of the network refresh once it ran again', async () => {
    steps.redisGetPulseState.mockResolvedValue({ last_error: 'network_refresh_failed' });
    steps.isPulseRefreshDeferred.mockReturnValue(false);
    await pulseManager();
    expect(steps.redisSetPulseState).toHaveBeenCalledWith({ last_error: undefined });
  });
});
