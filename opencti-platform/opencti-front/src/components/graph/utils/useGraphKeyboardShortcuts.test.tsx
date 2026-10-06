import React, { useRef } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render } from '@testing-library/react';
import useGraphKeyboardShortcuts, { type GraphShortcutHandlers } from './useGraphKeyboardShortcuts';

const handlers = (): GraphShortcutHandlers => ({
  fit: vi.fn(),
  fitSelection: vi.fn(),
  locate: vi.fn(),
  zoomIn: vi.fn(),
  zoomOut: vi.fn(),
  selectAll: vi.fn(),
  selectNeighbours: vi.fn(),
  shortestPath: vi.fn(),
  hideSelection: vi.fn(),
  showHidden: vi.fn(),
  clearSelection: vi.fn(),
  toggleLegend: vi.fn(),
  toggleFullscreen: vi.fn(),
  exportImage: vi.fn(),
  focusSearch: vi.fn(),
  showShortcuts: vi.fn(),
  openContextMenu: vi.fn(),
});

const Harness = ({ shortcuts }: { shortcuts: GraphShortcutHandlers }) => {
  const ref = useRef<HTMLDivElement>(null);
  useGraphKeyboardShortcuts(ref, shortcuts);
  return <div ref={ref} data-testid="graph" />;
};

describe('useGraphKeyboardShortcuts', () => {
  // A menu answers its Escape on the document before the graph does, then leaves the page.
  const answerEscape = (event: KeyboardEvent) => {
    if (event.key === 'Escape') event.preventDefault();
  };
  afterEach(() => document.removeEventListener('keydown', answerEscape, true));

  it('runs a shortcut while the pointer is over the graph, and not once it left', () => {
    const shortcuts = handlers();
    const { getByTestId } = render(<Harness shortcuts={shortcuts} />);
    fireEvent.mouseEnter(getByTestId('graph'));
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(shortcuts.clearSelection).toHaveBeenCalledTimes(1);
    fireEvent.mouseLeave(getByTestId('graph'));
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(shortcuts.clearSelection).toHaveBeenCalledTimes(1);
  });

  it('leaves the selection alone when the Escape closed a menu', () => {
    const shortcuts = handlers();
    const { getByTestId } = render(<Harness shortcuts={shortcuts} />);
    fireEvent.mouseEnter(getByTestId('graph'));
    document.addEventListener('keydown', answerEscape, true);
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(shortcuts.clearSelection).not.toHaveBeenCalled();
    fireEvent.keyDown(document, { key: 'p' });
    expect(shortcuts.shortestPath).toHaveBeenCalledTimes(1);
  });
});
