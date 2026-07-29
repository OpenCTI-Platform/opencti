import React from 'react';
import { act, render, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const useLazyLoadQueryMock = vi.fn();

vi.mock('react-relay', () => ({
  graphql: (strings: TemplateStringsArray) => strings,
  useLazyLoadQuery: (...args: unknown[]) => useLazyLoadQueryMock(...args),
}));

import { ConnectorManagerStatusProvider } from './ConnectorManagerStatusContext';

describe('ConnectorManagerStatusProvider', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('polls catalogVersionInfo and emits revision changes only when revision changes', async () => {
    vi.useFakeTimers();

    try {
      const onCatalogVersionChange = vi.fn();

      useLazyLoadQueryMock.mockImplementation((_query: unknown, _variables: unknown, options: { fetchKey?: number }) => {
        const fetchKey = options?.fetchKey ?? 0;
        const revision = fetchKey >= 2 ? 'rev-2' : 'rev-1';

        return {
          connectorManagers: [],
          catalogVersionInfo: {
            status: 'ready',
            revision,
            updated_at: '2026-07-29T10:00:00.000Z',
          },
        };
      });

      render(
        <ConnectorManagerStatusProvider onCatalogVersionChange={onCatalogVersionChange}>
          <div data-testid="child">child</div>
        </ConnectorManagerStatusProvider>,
      );

      await waitFor(() => {
        expect(onCatalogVersionChange).toHaveBeenCalledWith('rev-1');
      });
      expect(onCatalogVersionChange).toHaveBeenCalledTimes(1);

      act(() => {
        vi.advanceTimersByTime(30000);
      });

      // Same revision after first poll should not trigger another callback.
      await waitFor(() => {
        expect(onCatalogVersionChange).toHaveBeenCalledTimes(1);
      });

      act(() => {
        vi.advanceTimersByTime(30000);
      });

      await waitFor(() => {
        expect(onCatalogVersionChange).toHaveBeenCalledWith('rev-2');
      });
      expect(onCatalogVersionChange).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
