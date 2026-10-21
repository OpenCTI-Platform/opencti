import React from 'react';
import { describe, expect, it } from 'vitest';
import testRender from '../../utils/tests/test-render';
import ListCardsContent from './ListCardsContent';

const CardComponent = () => <div />;

const buildProps = (ids: string[]) => ({
  initialLoading: false,
  loadMore: () => {},
  hasMore: () => false,
  isLoading: () => false,
  dataList: ids.map((id) => ({ node: { id } })),
  globalCount: ids.length,
  CardComponent,
  DummyCardComponent: CardComponent,
  nbOfCardsToLoad: 25,
});

describe('ListCardsContent', () => {
  it('should accept new data before the list has been measured', () => {
    const { rerender } = testRender(<ListCardsContent {...buildProps(['a'])} />);

    expect(() => rerender(<ListCardsContent {...buildProps(['a', 'b'])} />)).not.toThrow();
  });
});
