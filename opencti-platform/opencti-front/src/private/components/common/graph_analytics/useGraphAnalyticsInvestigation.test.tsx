import { afterEach, describe, expect, it, vi } from 'vitest';
import { testRenderHook } from '../../../../utils/tests/test-render';
import { MESSAGING$ } from '../../../../relay/environment';
import useGraphAnalyticsInvestigation, { GRAPH_INVESTIGATION_MAX_ELEMENTS } from './useGraphAnalyticsInvestigation';

const commit = vi.fn();
vi.mock('../../../../utils/hooks/useApiMutation', () => ({ default: () => [commit, false] }));

const ids = (count: number) => Array.from({ length: count }, (_, i) => `entity-${i}`);

describe('useGraphAnalyticsInvestigation', () => {
  afterEach(() => {
    commit.mockReset();
    vi.restoreAllMocks();
  });

  it('refuses a result larger than an investigation can start with instead of cutting it', () => {
    const notifyError = vi.spyOn(MESSAGING$, 'notifyError').mockImplementation(() => undefined);
    const { hook } = testRenderHook(() => useGraphAnalyticsInvestigation());
    // duplicates are counted once: one element more than the limit once deduplicated
    hook.result.current.startInvestigation('Similar to Sandstorm Lynx', [...ids(GRAPH_INVESTIGATION_MAX_ELEMENTS + 1), 'entity-0'], 'similar_investigation');
    expect(commit).not.toHaveBeenCalled();
    expect(notifyError).toHaveBeenCalledTimes(1);
    expect(String(notifyError.mock.calls[0][0])).toMatch(/^This result holds 2,001 elements, more than the 2,000/);
  });

  it('starts the investigation with every element of a result within the limit', () => {
    const { hook } = testRenderHook(() => useGraphAnalyticsInvestigation());
    hook.result.current.startInvestigation('Similar to Sandstorm Lynx', [...ids(GRAPH_INVESTIGATION_MAX_ELEMENTS), 'entity-0'], 'similar_investigation');
    expect(commit).toHaveBeenCalledTimes(1);
    expect(commit.mock.calls[0][0].variables.input.investigated_entities_ids).toHaveLength(GRAPH_INVESTIGATION_MAX_ELEMENTS);
  });
});
