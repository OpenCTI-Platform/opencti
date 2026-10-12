import { act, screen, within } from '@testing-library/react';
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import HubCountBadge, { COUNT_RETRY_DELAY_MS } from '../../common/hub/HubCountBadge';
import { provenanceCurationCountFetchKey, useStaleKnowledgeCount } from './provenanceCurationCounts';

vi.mock('../../../../utils/hooks/useEntitySettings', () => ({ default: () => [] }));

describe('Provenance curation counts', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it('keeps the fetch key of the tab counters until the count failed, then changes it at each retry', () => {
    expect(provenanceCurationCountFetchKey(3, 0)).toEqual(3);
    expect(provenanceCurationCountFetchKey(3, 1)).not.toEqual(provenanceCurationCountFetchKey(3, 0));
    expect(provenanceCurationCountFetchKey(3, 2)).not.toEqual(provenanceCurationCountFetchKey(3, 1));
  });

  it('sends a new request for a badge whose count failed, and shows its answer', async () => {
    vi.useFakeTimers();
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const { relayEnv } = testRender(<span data-testid="tab"><HubCountBadge useCount={useStaleKnowledgeCount} /></span>);
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    await act(async () => {
      relayEnv.mock.rejectMostRecentOperation(new Error('count unavailable'));
    });
    expect(screen.getByTestId('tab').textContent).toEqual('');
    expect(relayEnv.mock.getAllOperations()).toHaveLength(0);
    act(() => {
      vi.advanceTimersByTime(COUNT_RETRY_DELAY_MS);
    });
    expect(relayEnv.mock.getAllOperations()).toHaveLength(1);
    await act(async () => {
      relayEnv.mock.resolveMostRecentOperation({
        data: { entities: { total: 3 }, relationships: { total: 1 }, sightings: { total: 0 } },
      });
    });
    expect(within(screen.getByTestId('tab')).getByText('4')).toBeInTheDocument();
  });
});
