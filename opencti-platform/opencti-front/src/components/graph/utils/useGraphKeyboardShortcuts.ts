import { MutableRefObject, useEffect, useRef } from 'react';

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

const isEditable = (target: EventTarget | null) => {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName);
};

const OVERLAY_SELECTOR = '.MuiDialog-root, .MuiDrawer-modal, .MuiPopover-root, [role="dialog"][aria-modal="true"], [role="menu"]';
const HIDDEN_SELECTOR = '.MuiModal-hidden, [aria-hidden="true"], [hidden]';

/**
 * A dialog, drawer or menu open over the graph owns the keyboard. Overlays kept mounted while
 * closed (`keepMounted`, for example the export loader of the container header) do not count.
 */
export const isOverlayOpen = (root: ParentNode = document) => Array.from(root.querySelectorAll(OVERLAY_SELECTOR))
  .some((overlay) => !overlay.closest(HIDDEN_SELECTOR));

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
 * and never while typing in a field or while a dialog, drawer or menu is open.
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
      if (isEditable(event.target) || isOverlayOpen()) return;
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
