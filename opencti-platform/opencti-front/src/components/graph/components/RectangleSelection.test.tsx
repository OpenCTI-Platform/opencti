import React from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import RectangleSelection, { RectangleSelectionProps } from './RectangleSelection';

// Offset of the graph canvas in the viewport, as it never sits at the document
// origin in the application (left navigation and top bar).
const CANVAS_LEFT = 100;
const CANVAS_TOP = 50;

const renderSelection = (props?: Partial<RectangleSelectionProps>) => {
  const onSelection = vi.fn();
  const { container, unmount } = testRender(
    <RectangleSelection onSelection={onSelection} {...props}>
      <div>
        <button type="button">Toolbar</button>
        <canvas />
      </div>
    </RectangleSelection>,
  );

  const canvas = container.querySelector('canvas') as HTMLCanvasElement;
  canvas.getBoundingClientRect = () => ({
    left: CANVAS_LEFT,
    top: CANVAS_TOP,
    right: CANVAS_LEFT + 800,
    bottom: CANVAS_TOP + 600,
    width: 800,
    height: 600,
    x: CANVAS_LEFT,
    y: CANVAS_TOP,
    toJSON: () => ({}),
  }) as DOMRect;

  return { canvas, toolbar: screen.getByRole('button'), onSelection, unmount };
};

const overlay = () => screen.queryByTestId('rectangle-selection-overlay');

describe('RectangleSelection', () => {
  it('renders its children and no overlay before any interaction', () => {
    const { onSelection } = renderSelection();
    expect(overlay()).toBeNull();
    expect(onSelection).not.toHaveBeenCalled();
  });

  it('ignores a plain click without any move', () => {
    const { canvas, onSelection } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 0, clientX: 150, clientY: 100 });
    fireEvent.mouseUp(document);
    expect(overlay()).toBeNull();
    expect(onSelection).not.toHaveBeenCalled();
  });

  it('reports coordinates relative to the graph canvas', () => {
    const { canvas, onSelection } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 0, clientX: 150, clientY: 100 });
    fireEvent.mouseMove(document, { clientX: 350, clientY: 250 });
    fireEvent.mouseUp(document);
    expect(onSelection).toHaveBeenCalledTimes(1);
    expect(onSelection.mock.calls[0][0]).toEqual({
      origin: [150 - CANVAS_LEFT, 100 - CANVAS_TOP],
      target: [350 - CANVAS_LEFT, 250 - CANVAS_TOP],
    });
  });

  it('normalizes a rectangle dragged towards the top left', () => {
    const { canvas, onSelection } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 0, clientX: 350, clientY: 250 });
    fireEvent.mouseMove(document, { clientX: 150, clientY: 100 });
    fireEvent.mouseUp(document);
    expect(onSelection.mock.calls[0][0]).toEqual({
      origin: [150 - CANVAS_LEFT, 100 - CANVAS_TOP],
      target: [350 - CANVAS_LEFT, 250 - CANVAS_TOP],
    });
  });

  it('forwards the modifier keys held during the drag', () => {
    const { canvas, onSelection } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 0, clientX: 150, clientY: 100 });
    fireEvent.mouseMove(document, { clientX: 350, clientY: 250, shiftKey: true, altKey: true });
    fireEvent.mouseUp(document);
    expect(onSelection.mock.calls[0][1]).toEqual({ altKey: true, shiftKey: true });
  });

  it('draws the overlay over the dragged area', () => {
    const { canvas } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 0, clientX: 350, clientY: 250 });
    fireEvent.mouseMove(document, { clientX: 150, clientY: 100 });
    expect(overlay()).toHaveStyle({
      left: `${150 - CANVAS_LEFT}px`,
      top: `${100 - CANVAS_TOP}px`,
      width: '200px',
      height: '150px',
    });
  });

  it('clears the overlay once the drag is released', () => {
    const { canvas } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 0, clientX: 150, clientY: 100 });
    fireEvent.mouseMove(document, { clientX: 350, clientY: 250 });
    expect(overlay()).not.toBeNull();
    fireEvent.mouseUp(document);
    expect(overlay()).toBeNull();
  });

  it('keeps tracking a drag that runs outside the graph', () => {
    const { canvas, onSelection } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 0, clientX: 150, clientY: 100 });
    fireEvent.mouseMove(document, { clientX: 350, clientY: 250 });
    // The cursor leaves the graph, the rectangle must keep following it.
    fireEvent.mouseOut(canvas, { relatedTarget: document.body });
    fireEvent.mouseMove(document, { clientX: 900, clientY: 700 });
    fireEvent.mouseUp(document);
    expect(onSelection).toHaveBeenCalledTimes(1);
    expect(onSelection.mock.calls[0][0]).toEqual({
      origin: [150 - CANVAS_LEFT, 100 - CANVAS_TOP],
      target: [900 - CANVAS_LEFT, 700 - CANVAS_TOP],
    });
  });

  it('does not start a selection outside the graph canvas', () => {
    const { toolbar, onSelection } = renderSelection();
    fireEvent.mouseDown(toolbar, { button: 0, clientX: 150, clientY: 100 });
    fireEvent.mouseMove(document, { clientX: 350, clientY: 250 });
    fireEvent.mouseUp(document);
    expect(overlay()).toBeNull();
    expect(onSelection).not.toHaveBeenCalled();
  });

  it('does not start a selection on a non-primary button', () => {
    const { canvas, onSelection } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 2, clientX: 150, clientY: 100 });
    fireEvent.mouseMove(document, { clientX: 350, clientY: 250 });
    fireEvent.mouseUp(document);
    expect(overlay()).toBeNull();
    expect(onSelection).not.toHaveBeenCalled();
  });

  it('does nothing when disabled', () => {
    const { canvas, onSelection } = renderSelection({ disabled: true });
    fireEvent.mouseDown(canvas, { button: 0, clientX: 150, clientY: 100 });
    fireEvent.mouseMove(document, { clientX: 350, clientY: 250 });
    fireEvent.mouseUp(document);
    expect(overlay()).toBeNull();
    expect(onSelection).not.toHaveBeenCalled();
  });

  it('releases the document listeners when unmounted mid-drag', () => {
    const { canvas, onSelection, unmount } = renderSelection();
    fireEvent.mouseDown(canvas, { button: 0, clientX: 150, clientY: 100 });
    fireEvent.mouseMove(document, { clientX: 350, clientY: 250 });
    unmount();
    fireEvent.mouseUp(document);
    expect(onSelection).not.toHaveBeenCalled();
  });
});
