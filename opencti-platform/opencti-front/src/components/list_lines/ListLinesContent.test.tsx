import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import ListLinesContent from './ListLinesContent';

const autoSizer = vi.hoisted(() => ({ width: 0 }));

vi.mock('react-virtualized-auto-sizer', () => ({
  AutoSizer: ({ renderProp }: { renderProp: (size: { width: number; height: undefined }) => React.ReactNode }) => renderProp({ width: autoSizer.width, height: undefined }),
}));

const LineComponent = ({ node }: { node?: { id: string } }) => <div>{node?.id}</div>;

const buildProps = (ids: string[]) => ({
  initialLoading: false,
  loadMore: () => {},
  hasMore: () => false,
  isLoading: () => false,
  dataList: ids.map((id) => ({ node: { id } })),
  globalCount: ids.length,
  LineComponent,
  DummyLineComponent: LineComponent,
  nbOfRowsToLoad: 25,
  dataColumns: {},
  disableExport: true,
});

describe('ListLinesContent', () => {
  beforeEach(() => {
    autoSizer.width = 0;
  });

  it('should accept new data before the list has been measured', () => {
    const { rerender } = testRender(<ListLinesContent {...buildProps(['a'])} />);

    expect(() => rerender(<ListLinesContent {...buildProps(['a', 'b'])} />)).not.toThrow();
  });

  it('should render the rows in a grid once the list has been measured', () => {
    autoSizer.width = 1000;
    const { rerender } = testRender(<ListLinesContent {...buildProps(['a'])} />);

    expect(screen.getByRole('grid')).toBeInTheDocument();
    expect(screen.getByText('a')).toBeInTheDocument();

    rerender(<ListLinesContent {...buildProps(['a', 'b'])} />);

    expect(screen.getByText('b')).toBeInTheDocument();
  });
});
