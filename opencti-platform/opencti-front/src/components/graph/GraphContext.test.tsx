import React from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../utils/tests/test-render';
import { GraphProvider, useGraphContext } from './GraphContext';
import { readHiddenNodeIds, writeHiddenNodeIds } from './utils/graphHiddenNodes';

const HiddenEntities = () => {
  const { graphState } = useGraphContext();
  return <span data-testid="hidden">{(graphState.hiddenNodeIds ?? []).join(',')}</span>;
};

describe('GraphProvider', () => {
  afterEach(() => {
    writeHiddenNodeIds('graph-a', []);
    writeHiddenNodeIds('graph-b', []);
  });

  it('starts over with the hidden entities of the next graph when it stays mounted from one graph to the next', () => {
    writeHiddenNodeIds('graph-a', ['a1']);
    writeHiddenNodeIds('graph-b', ['b1']);
    const { rerender } = testRender(
      <GraphProvider objects={[]} localStorageKey="graph-a"><HiddenEntities /></GraphProvider>,
    );
    expect(screen.getByTestId('hidden')).toHaveTextContent('a1');
    rerender(<GraphProvider objects={[]} localStorageKey="graph-b"><HiddenEntities /></GraphProvider>);
    expect(screen.getByTestId('hidden')).toHaveTextContent(/^b1$/);
    expect(readHiddenNodeIds('graph-a')).toEqual(['a1']);
    expect(readHiddenNodeIds('graph-b')).toEqual(['b1']);
  });
});
