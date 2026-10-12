import { beforeEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../../src/config/conf';
import { queueValidationTracking } from '../../../../src/modules/defenseCoverage/defenseCoverage-domain';
import { queuePendingValidationTracking } from '../../../../src/modules/defenseCoverage/defenseCoverage-state';
import type { BasicStoreEntity } from '../../../../src/types/store';

vi.mock('../../../../src/modules/defenseCoverage/defenseCoverage-state', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/defenseCoverage/defenseCoverage-state')>()),
  queuePendingValidationTracking: vi.fn(async () => undefined),
}));

const REQUEST = {
  security_coverage_id: 'security-coverage-1',
  grouping_id: 'grouping-1',
  threat_id: 'threat-1',
  requested_at: '2026-10-07T05:00:00.000Z',
  requested_by: 'user-1',
};
const ATTACK_PATTERNS = [{ internal_id: 'attack-pattern-1' }, { internal_id: 'attack-pattern-2' }] as BasicStoreEntity[];
const TARGETS = Array.from({ length: 1500 }, (_, index) => ({ attackPatternId: `attack-pattern-${(index % 2) + 1}`, platformId: `platform-${index}` }));

describe('Defense validation tracking queue', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.mocked(queuePendingValidationTracking).mockReset();
  });

  it('should log only the identifiers of the request and the number of its targets when it cannot be queued', async () => {
    const cause = new Error('tracking failed');
    const queueError = new Error('queue unavailable');
    vi.mocked(queuePendingValidationTracking).mockRejectedValueOnce(queueError);
    const logAppErrorSpy = vi.spyOn(logApp, 'error').mockImplementation(() => undefined);
    await expect(queueValidationTracking(ATTACK_PATTERNS, TARGETS, REQUEST, cause)).resolves.toEqual(0);
    expect(logAppErrorSpy).toHaveBeenCalledTimes(1);
    // Neither the requester, the threat nor the list of targets reaches the log
    expect(logAppErrorSpy.mock.calls[0][1]).toStrictEqual({
      cause,
      queue_cause: queueError,
      security_coverage_id: 'security-coverage-1',
      grouping_id: 'grouping-1',
      targets: 1500,
    });
  });

  it('should queue the targets of the found techniques and return their number', async () => {
    vi.spyOn(logApp, 'warn').mockImplementation(() => undefined);
    const targets = [...TARGETS.slice(0, 2), { attackPatternId: 'attack-pattern-unknown', platformId: 'platform-x' }];
    await expect(queueValidationTracking(ATTACK_PATTERNS, targets, REQUEST, new Error('tracking failed'))).resolves.toEqual(2);
    expect(vi.mocked(queuePendingValidationTracking)).toHaveBeenCalledWith({ request: REQUEST, targets: TARGETS.slice(0, 2) });
  });
});
