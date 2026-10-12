import { beforeEach, describe, expect, it, vi } from 'vitest';

const steps = vi.hoisted(() => ({
  runPulsePendingCleanup: vi.fn(),
  runPulseContribution: vi.fn(),
  runPulseRefresh: vi.fn(),
  runPulsePreview: vi.fn(),
  runPulseTrendingNotifications: vi.fn(),
  redisGetPulseState: vi.fn(),
  redisSetPulseState: vi.fn(),
}));

vi.mock('../../../src/modules/xtm/pulse/pulse-domain', () => ({
  runPulsePendingCleanup: steps.runPulsePendingCleanup,
  runPulseContribution: steps.runPulseContribution,
  runPulseRefresh: steps.runPulseRefresh,
  runPulsePreview: steps.runPulsePreview,
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
});
