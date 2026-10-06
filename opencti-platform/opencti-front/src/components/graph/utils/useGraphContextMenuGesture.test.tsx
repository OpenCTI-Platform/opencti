import React, { useRef } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { createEvent, fireEvent, render } from '@testing-library/react';
import useGraphContextMenuGesture, { CONTEXT_MENU_MOVE_TOLERANCE, IS_MAC, isAdditiveClick } from './useGraphContextMenuGesture';

const Harness = ({ onOpen }: { onOpen: (point: { clientX: number; clientY: number }) => void }) => {
  const ref = useRef<HTMLDivElement>(null);
  useGraphContextMenuGesture(ref, true, onOpen);
  return (
    <div ref={ref}>
      <canvas data-testid="canvas" />
      <input data-testid="field" />
    </div>
  );
};

describe('useGraphContextMenuGesture', () => {
  it('opens on a right press released in place, and never after a drag', () => {
    const onOpen = vi.fn();
    const { getByTestId } = render(<Harness onOpen={onOpen} />);
    const canvas = getByTestId('canvas');
    fireEvent.mouseDown(canvas, { button: 2, clientX: 10, clientY: 10 });
    fireEvent.mouseUp(canvas, { button: 2, clientX: 10 + CONTEXT_MENU_MOVE_TOLERANCE, clientY: 10 });
    expect(onOpen).toHaveBeenCalledWith({ clientX: 10 + CONTEXT_MENU_MOVE_TOLERANCE, clientY: 10 });
    onOpen.mockClear();
    // The relationship drag, released anywhere on the page
    fireEvent.mouseDown(canvas, { button: 2, clientX: 10, clientY: 10 });
    fireEvent.mouseUp(document, { button: 2, clientX: 60, clientY: 40 });
    // A left press is no menu request
    fireEvent.mouseDown(canvas, { button: 0, clientX: 10, clientY: 10 });
    fireEvent.mouseUp(canvas, { button: 2, clientX: 10, clientY: 10 });
    expect(onOpen).not.toHaveBeenCalled();
  });

  it('opens nothing after a drag released back near where it started', () => {
    const onOpen = vi.fn();
    const { getByTestId } = render(<Harness onOpen={onOpen} />);
    const canvas = getByTestId('canvas');
    fireEvent.mouseDown(canvas, { button: 2, clientX: 10, clientY: 10 });
    fireEvent.mouseMove(document, { button: 2, clientX: 60, clientY: 10 });
    fireEvent.mouseMove(document, { button: 2, clientX: 11, clientY: 10 });
    fireEvent.mouseUp(canvas, { button: 2, clientX: 11, clientY: 10 });
    expect(onOpen).not.toHaveBeenCalled();
    // The next press starts over: released in place, it opens the menu.
    fireEvent.mouseDown(canvas, { button: 2, clientX: 10, clientY: 10 });
    fireEvent.mouseUp(canvas, { button: 2, clientX: 10, clientY: 10 });
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it('keeps the menu of the browser off the canvas, and on the fields', () => {
    const onOpen = vi.fn();
    const { getByTestId } = render(<Harness onOpen={onOpen} />);
    const onCanvas = createEvent.contextMenu(getByTestId('canvas'), { button: 2 });
    fireEvent(getByTestId('canvas'), onCanvas);
    expect(onCanvas.defaultPrevented).toBe(true);
    // The right button opens the menu on its release only
    expect(onOpen).not.toHaveBeenCalled();
    // A long press on a touch screen, or a macOS Control click, reports the left button
    fireEvent.contextMenu(getByTestId('canvas'), { button: 0, clientX: 7, clientY: 9 });
    expect(onOpen).toHaveBeenCalledWith({ clientX: 7, clientY: 9 });
    const onField = createEvent.contextMenu(getByTestId('field'), { button: 0 });
    fireEvent(getByTestId('field'), onField);
    expect(onField.defaultPrevented).toBe(false);
  });

  it('adds to the selection with Shift, Alt and Command, and with Control outside macOS', () => {
    const keys = { shiftKey: false, altKey: false, metaKey: false, ctrlKey: false };
    expect(isAdditiveClick(keys)).toBe(false);
    expect(isAdditiveClick({ ...keys, shiftKey: true })).toBe(true);
    expect(isAdditiveClick({ ...keys, altKey: true })).toBe(true);
    expect(isAdditiveClick({ ...keys, metaKey: true })).toBe(true);
    expect(isAdditiveClick({ ...keys, ctrlKey: true })).toBe(!IS_MAC);
  });
});
