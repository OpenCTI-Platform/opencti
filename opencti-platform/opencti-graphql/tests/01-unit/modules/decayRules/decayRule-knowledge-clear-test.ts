import { beforeEach, describe, expect, it, vi } from 'vitest';
import { clearFreshnessFlagsOfRule, clearOutdatedFreshnessFlags } from '../../../../src/modules/decayRule/decayRule-knowledge';
import type { BasicStoreEntityDecayRule } from '../../../../src/modules/decayRule/decayRule-types';

const mockElRawUpdateByQuery = vi.fn();

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/engine')>()),
  elRawUpdateByQuery: (...args: unknown[]) => mockElRawUpdateByQuery(...args),
}));

vi.mock('../../../../src/database/utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/utils')>()),
  wait: () => Promise.resolve(),
}));

describe('Knowledge decay rule - clearing the stale flags of a rule', () => {
  beforeEach(() => {
    mockElRawUpdateByQuery.mockReset();
  });

  it('should clear again the elements skipped as version conflicts', async () => {
    mockElRawUpdateByQuery
      .mockResolvedValueOnce({ updated: 3, version_conflicts: 2, failures: [] })
      .mockResolvedValueOnce({ updated: 2, version_conflicts: 0, failures: [] });
    await clearFreshnessFlagsOfRule('rule-id');
    expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(2);
    const [first, second] = mockElRawUpdateByQuery.mock.calls.map(([query]) => query);
    expect(first.body.query).toEqual({ term: { 'freshness_rule_id.keyword': 'rule-id' } });
    expect(second.body.query).toEqual(first.body.query);
  });

  it('should fail rather than leave a flag behind when the elements keep changing', async () => {
    mockElRawUpdateByQuery.mockResolvedValue({ updated: 0, version_conflicts: 1, failures: [] });
    await expect(clearFreshnessFlagsOfRule('rule-id')).rejects.toThrow('Knowledge freshness flags kept changing while they were cleared');
    expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(5);
  });

  it('should fail at once on a failure other than a version conflict', async () => {
    mockElRawUpdateByQuery.mockResolvedValue({ updated: 0, version_conflicts: 0, failures: [{ cause: { type: 'script_exception' } }] });
    await expect(clearFreshnessFlagsOfRule('rule-id')).rejects.toThrow('Error clearing knowledge freshness flags');
    expect(mockElRawUpdateByQuery).toHaveBeenCalledTimes(1);
  });

  it('should clear the flags of inactive rules and the flags set before the last configuration of their rule', async () => {
    mockElRawUpdateByQuery.mockResolvedValue({ updated: 1, version_conflicts: 0, failures: [] });
    const configuredAt = '2026-10-06T10:00:00.000Z';
    const rule = (fields: Partial<BasicStoreEntityDecayRule>) => fields as BasicStoreEntityDecayRule;
    await clearOutdatedFreshnessFlags([rule({ id: 'configured-rule', freshness_configured_at: configuredAt }), rule({ id: 'older-rule' })]);
    const [[{ body }]] = mockElRawUpdateByQuery.mock.calls;
    expect(body.query).toEqual({
      bool: {
        must: [{ term: { freshness_stale: true } }],
        should: [
          { bool: { must_not: [{ terms: { 'freshness_rule_id.keyword': ['configured-rule', 'older-rule'] } }] } },
          { bool: { must: [{ term: { 'freshness_rule_id.keyword': 'configured-rule' } }, { range: { freshness_stale_at: { lt: configuredAt } } }] } },
        ],
        minimum_should_match: 1,
      },
    });
  });

  it('should clear every flag when no rule is active', async () => {
    mockElRawUpdateByQuery.mockResolvedValue({ updated: 0, version_conflicts: 0, failures: [] });
    await clearOutdatedFreshnessFlags([]);
    const [[{ body }]] = mockElRawUpdateByQuery.mock.calls;
    expect(body.query.bool.should).toEqual([{ bool: { must_not: [{ terms: { 'freshness_rule_id.keyword': [] } }] } }]);
  });
});
