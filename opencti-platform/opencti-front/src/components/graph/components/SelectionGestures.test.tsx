import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import { graphNode } from '../../../utils/tests/graphTestData';
import { createRecordingContext } from '../../../utils/tests/recordingCanvasContext';
import LassoSelection from './LassoSelection';
import RelationSelection from './RelationSelection';

// The screen and the graph share their coordinates: a gesture selects what it is drawn over.
const graph = {
  current: { screen2GraphCoords: (x: number, y: number) => ({ x, y }), graph2ScreenCoords: (x: number, y: number) => ({ x, y }) },
} as never;
const at = (clientX: number, clientY: number, button = 0) => ({ clientX, clientY, button });

beforeEach(() => {
  const context = createRecordingContext();
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(context as never);
});

afterEach(() => vi.restoreAllMocks());

describe('LassoSelection', () => {
  const inside = graphNode({ id: 'inside', x: 50, y: 50 });
  const outside = graphNode({ id: 'outside', x: 500, y: 500 });

  const renderLasso = () => {
    const setSelectedNodes = vi.fn();
    const { container } = testRender(
      <LassoSelection width={800} height={600} activated graphDataNodes={[inside, outside]} graph={graph} setSelectedNodes={setSelectedNodes} />,
    );
    return { setSelectedNodes, canvas: container.querySelector('#lasso-canvas') as HTMLCanvasElement };
  };

  it('selects what the path encloses when the button is released outside the canvas, then lets go', () => {
    const { setSelectedNodes, canvas } = renderLasso();
    fireEvent.mouseDown(canvas, at(10, 10));
    // No move is reported at the press point: the path starts there all the same.
    [at(100, 10), at(100, 100), at(10, 100)].forEach((point) => fireEvent.mouseMove(document, point));
    fireEvent.mouseUp(document.body, at(10, 100));
    expect(setSelectedNodes).toHaveBeenCalledTimes(1);
    expect([...setSelectedNodes.mock.calls[0][0]]).toEqual([inside]);
    // The gesture is over: a later release selects nothing more.
    fireEvent.mouseUp(canvas, at(10, 100));
    expect(setSelectedNodes).toHaveBeenCalledTimes(1);
  });

  it('reads the pointer in viewport coordinates, like the canvas box, on a scrolled page', () => {
    const scroll = { scrollX: 0, scrollY: 400, pageXOffset: 0, pageYOffset: 400 };
    Object.entries(scroll).forEach(([key, value]) => Object.defineProperty(window, key, { value, configurable: true }));
    try {
      const { setSelectedNodes, canvas } = renderLasso();
      fireEvent.mouseDown(canvas, at(10, 10));
      [at(100, 10), at(100, 100), at(10, 100)].forEach((point) => fireEvent.mouseMove(document, point));
      fireEvent.mouseUp(canvas, at(10, 100));
      expect([...setSelectedNodes.mock.calls[0][0]]).toEqual([inside]);
    } finally {
      Object.keys(scroll).forEach((key) => Object.defineProperty(window, key, { value: 0, configurable: true }));
    }
  });

  it('is drawn with the left button only', () => {
    const { setSelectedNodes, canvas } = renderLasso();
    [1, 2].forEach((button) => {
      fireEvent.mouseDown(canvas, at(10, 10, button));
      [at(100, 10, button), at(100, 100, button), at(10, 100, button)].forEach((point) => fireEvent.mouseMove(document, point));
      fireEvent.mouseUp(document.body, at(10, 100, button));
    });
    expect(setSelectedNodes).not.toHaveBeenCalled();
  });

  it('starts nothing on a canvas outside the graph', () => {
    const { setSelectedNodes } = renderLasso();
    const elsewhere = document.createElement('canvas');
    document.body.appendChild(elsewhere);
    fireEvent.mouseDown(elsewhere, at(10, 10));
    fireEvent.mouseUp(elsewhere, at(10, 100));
    expect(setSelectedNodes).not.toHaveBeenCalled();
    elsewhere.remove();
  });
});

describe('RelationSelection', () => {
  const from = graphNode({ id: 'from', x: 10, y: 10 });
  const to = graphNode({ id: 'to', x: 100, y: 10 });

  const renderRelation = () => {
    const setSelectedNodes = vi.fn();
    const { container } = testRender(
      <RelationSelection width={800} height={600} activated graphDataNodes={[from, to]} graph={graph} setSelectedNodes={setSelectedNodes} />,
    );
    return { setSelectedNodes, canvas: container.querySelector('#relation-canvas') as HTMLCanvasElement };
  };

  it('links the first and last nodes of a right-button drag released outside the canvas', () => {
    const { setSelectedNodes, canvas } = renderRelation();
    fireEvent.mouseDown(canvas, at(10, 10, 2));
    // The first move already lands on the target: the source is the node under the press.
    fireEvent.mouseMove(document, at(100, 10, 2));
    fireEvent.mouseUp(document.body, at(150, 10, 2));
    expect(setSelectedNodes).toHaveBeenCalledTimes(1);
    expect([...setSelectedNodes.mock.calls[0][0]]).toEqual([from, to]);
  });

  it('leaves every other release of the page untouched', () => {
    const { setSelectedNodes } = renderRelation();
    const button = document.createElement('button');
    document.body.appendChild(button);
    const onWindowUp = vi.fn();
    window.addEventListener('mouseup', onWindowUp);
    // `fireEvent` returns false when the default action was prevented.
    expect(fireEvent.mouseUp(button, at(5, 5))).toBe(true);
    expect(fireEvent.mouseUp(button, at(5, 5, 2))).toBe(true);
    expect(onWindowUp).toHaveBeenCalledTimes(2);
    expect(setSelectedNodes).not.toHaveBeenCalled();
    window.removeEventListener('mouseup', onWindowUp);
    button.remove();
  });

  it('keeps the context menu of the page, suppressing it over the graph only', () => {
    const { canvas } = renderRelation();
    const button = document.createElement('button');
    document.body.appendChild(button);
    expect(fireEvent.contextMenu(button)).toBe(true);
    expect(fireEvent.contextMenu(canvas)).toBe(false);
    button.remove();
  });
});
