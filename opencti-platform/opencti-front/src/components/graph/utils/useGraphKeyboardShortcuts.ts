import { MutableRefObject, useEffect, useRef } from 'react';
import { isEditable, isOverlayOpen } from '../../../utils/keyboard';

// Re-exported: these helpers moved to utils/keyboard, shared with the global search shortcut.
export { isOverlayOpen };

export interface GraphShortcutHandlers {
  fit: () => void;
  fitSelection: () => void;
  locate: () => void;
  zoomIn: () => void;
  zoomOut: () => void;
  selectAll: () => void;
  selectNeighbours: () => void;
  shortestPath: () => void;
  hideSelection: () => void;
  showHidden: () => void;
  clearSelection: () => void;
  toggleLegend: () => void;
  toggleFullscreen: () => void;
  exportImage: () => void;
  focusSearch: () => void;
  showShortcuts: () => void;
  openContextMenu: () => void;
}

/** The shortcut a key event stands for, or `null`; kept apart from the listener so it can be tested. */
export const shortcutOf = (event: Pick<KeyboardEvent, 'key' | 'shiftKey' | 'ctrlKey' | 'metaKey' | 'altKey'>): keyof GraphShortcutHandlers | null => {
  const modifier = event.ctrlKey || event.metaKey;
  if (!modifier && !event.altKey && (event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10'))) return 'openContextMenu';
  if (modifier && !event.altKey && event.key.toLowerCase() === 'a') return 'selectAll';
  if (modifier || event.altKey) return null;
  switch (event.key) {
    case 'f':
    case 'F':
      return event.shiftKey ? 'fitSelection' : 'fit';
    case 'l':
      return 'locate';
    case '+':
    case '=':
      return 'zoomIn';
    case '-':
    case '_':
      return 'zoomOut';
    case 'n':
      return 'selectNeighbours';
    case 'p':
      return 'shortestPath';
    case 'h':
      return 'hideSelection';
    case 'H':
      return 'showHidden';
    case 'Escape':
      return 'clearSelection';
    case 'g':
      return 'toggleLegend';
    case 'M':
      return 'toggleFullscreen';
    case 'E':
      return 'exportImage';
    case '/':
      return 'focusSearch';
    case '?':
      return 'showShortcuts';
    default:
      return null;
  }
};

/**
 * Keyboard shortcuts of a graph, active while the pointer is over it or the focus is inside it,
 * and never while typing in a field, while a dialog, drawer or menu is open, or for a key another
 * control already answered.
 */
const useGraphKeyboardShortcuts = (
  containerRef: MutableRefObject<HTMLElement | null>,
  handlers: GraphShortcutHandlers,
  enabled = true,
) => {
  const hovered = useRef(false);
  const latest = useRef(handlers);
  latest.current = handlers;

  useEffect(() => {
    const container = containerRef.current;
    if (!container || !enabled) return undefined;
    const enter = () => {
      hovered.current = true;
    };
    const leave = () => {
      hovered.current = false;
    };
    const onKeyDown = (event: KeyboardEvent) => {
      const focusedInside = container.contains(document.activeElement);
      if (!hovered.current && !focusedInside) return;
      // A menu closed by this Escape is gone from the page by now: it marked the key as answered.
      if (event.defaultPrevented || isEditable(event.target) || isOverlayOpen()) return;
      const shortcut = shortcutOf(event);
      if (!shortcut) return;
      event.preventDefault();
      latest.current[shortcut]();
    };
    container.addEventListener('mouseenter', enter);
    container.addEventListener('mouseleave', leave);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      container.removeEventListener('mouseenter', enter);
      container.removeEventListener('mouseleave', leave);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [containerRef, enabled]);
};

export default useGraphKeyboardShortcuts;
