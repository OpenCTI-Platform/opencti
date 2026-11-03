import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import ListCardsContent from './ListCardsContent';

const autoSizer = vi.hoisted(() => ({ width: 0 }));

vi.mock('react-virtualized-auto-sizer', () => ({
  AutoSizer: ({ renderProp }: { renderProp: (size: { width: number; height: undefined }) => React.ReactNode }) => renderProp({ width: autoSizer.width, height: undefined }),
}));

const CardComponent = ({ node }: { node?: { id: string } }) => <div>{node?.id}</div>;

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
  beforeEach(() => {
    autoSizer.width = 0;
  });

  it('should accept new data before the list has been measured', () => {
    const { rerender } = testRender(<ListCardsContent {...buildProps(['a'])} />);

    expect(() => rerender(<ListCardsContent {...buildProps(['a', 'b'])} />)).not.toThrow();
  });

  it('should render the cards in a grid once the list has been measured', () => {
    autoSizer.width = 1000;
    const { rerender } = testRender(<ListCardsContent {...buildProps(['a'])} />);

    expect(screen.getByRole('grid')).toBeInTheDocument();
    expect(screen.getByText('a')).toBeInTheDocument();

    rerender(<ListCardsContent {...buildProps(['a', 'b'])} />);

    expect(screen.getByText('b')).toBeInTheDocument();
  });
});
