import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import GraphToolbarTimeRange from './GraphToolbarTimeRange';

// jsdom gives the responsive chart no size: a plain box stands for it.
vi.mock('recharts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('recharts')>()),
  ResponsiveContainer: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

describe('GraphToolbarTimeRange', () => {
  it('draws the range it is given, outside any graph', () => {
    testRender(
      <GraphToolbarTimeRange
        timeRange={{ interval: [new Date('2026-01-01T00:00:00Z'), new Date('2026-06-01T00:00:00Z')], values: [] }}
        onChange={vi.fn()}
      />,
    );
    expect(screen.getAllByRole('slider').length).toBeGreaterThan(0);
  });
});
