import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../utils/tests/test-render';
import ListLinesContent from './ListLinesContent';

const LineComponent = () => <div />;

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
  it('should accept new data before the list has been measured', () => {
    const { rerender } = testRender(<ListLinesContent {...buildProps(['a'])} />);

    expect(() => rerender(<ListLinesContent {...buildProps(['a', 'b'])} />)).not.toThrow();
  });
});
