import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import { SinceLastVisitBatchProvider, SinceLastVisitRowBadge } from './SinceLastVisitBatch';

const mockFetchQuery = vi.fn();
vi.mock('../../../../relay/environment', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../relay/environment')>()),
  fetchQuery: (...args: unknown[]) => mockFetchQuery(...args),
}));

const row = (id: string) => ({ entity_id: id, first_visit: false, last_seen_at: '2026-10-01T00:00:00.000Z', new_relationships: 2, updates: 0, new_container_objects: 0 });
const answer = (value: unknown) => ({ toPromise: () => (value instanceof Error ? Promise.reject(value) : Promise.resolve(value)) });
const failure = () => answer(new Error('network'));

const renderBadge = () => testRender(
  <SinceLastVisitBatchProvider enabled>
    <SinceLastVisitRowBadge id="malware-1" entityType="Malware" />
  </SinceLastVisitBatchProvider>,
  { userContext: createMockUserContext({ schema: { sdos: [{ id: 'Malware' }], scos: [] } }) },
);

const elapse = async (ms: number) => {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
};

describe('Last visit badges of a list', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });
  afterEach(() => {
    vi.useRealTimers();
    mockFetchQuery.mockReset();
  });

  it('should request a failed batch again and show the badge once it is answered', async () => {
    mockFetchQuery.mockReturnValueOnce(failure()).mockReturnValueOnce(answer({ entitiesSinceLastVisit: [row('malware-1')] }));
    const { queryByTestId } = renderBadge();
    await elapse(200);
    expect(mockFetchQuery).toHaveBeenCalledTimes(1);
    expect(mockFetchQuery.mock.calls[0][1]).toEqual({ ids: ['malware-1'] });
    expect(queryByTestId('since-last-visit-row-badge')).toBeNull();
    await elapse(3100);
    expect(mockFetchQuery).toHaveBeenCalledTimes(2);
    expect(queryByTestId('since-last-visit-row-badge')).not.toBeNull();
  });

  it('should give the badge of a row up after three failed requests', async () => {
    mockFetchQuery.mockImplementation(failure);
    const { queryByTestId } = renderBadge();
    await elapse(20000);
    expect(mockFetchQuery).toHaveBeenCalledTimes(3);
    expect(queryByTestId('since-last-visit-row-badge')).toBeNull();
  });
});
