import { RefObject, useEffect, useRef } from 'react';

/** A right press that moves further than this is a drag (drawing a relationship), not a menu request. */
export const CONTEXT_MENU_MOVE_TOLERANCE = 4;

/** On macOS a Control click is the context menu of the system: the graph reads it as such. */
export const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

/** Whether a click adds to the selection: Shift, Alt, Command, and Control outside macOS. */
export const isAdditiveClick = (event: Pick<MouseEvent, 'ctrlKey' | 'shiftKey' | 'altKey' | 'metaKey'>) => event.shiftKey
  || event.altKey
  || event.metaKey
  || (event.ctrlKey && !IS_MAC);

const isEditable = (target: EventTarget | null) => target instanceof HTMLElement
  && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName));

/** Whether a left click is the macOS context-menu click, which opens the menu instead of selecting. */
export const isMacContextClick = (event: Pick<MouseEvent, 'ctrlKey' | 'button'>) => IS_MAC && event.ctrlKey && event.button === 0;

/**
 * The context-menu gesture of the graph canvases inside `containerRef`: the right button shares its
 * press with the relationship drag, as the left button shares it between a click and a drag. A right
 * press released within `CONTEXT_MENU_MOVE_TOLERANCE` pixels opens the menu where it was released;
 * past that it is the drag, and no menu opens. The browser menu never opens over the canvases.
 */
const useGraphContextMenuGesture = (
  containerRef: RefObject<HTMLElement | null>,
  enabled: boolean,
  onOpen: (point: { clientX: number; clientY: number }) => void,
) => {
  const latest = useRef(onOpen);
  latest.current = onOpen;
  useEffect(() => {
    const container = containerRef.current;
    if (!container || !enabled) return undefined;
    const isCanvas = (target: EventTarget | null) => target instanceof HTMLCanvasElement && container.contains(target);
    let press: { x: number; y: number } | null = null;
    const onDown = (event: MouseEvent) => {
      press = event.button === 2 && isCanvas(event.target) ? { x: event.clientX, y: event.clientY } : null;
    };
    // Registered on the document: the release of a press on the canvas may happen anywhere.
    const onUp = (event: MouseEvent) => {
      if (event.button !== 2 || !press) return;
      const moved = Math.hypot(event.clientX - press.x, event.clientY - press.y);
      press = null;
      if (moved <= CONTEXT_MENU_MOVE_TOLERANCE) latest.current({ clientX: event.clientX, clientY: event.clientY });
    };
    const onContextMenu = (event: MouseEvent) => {
      if (isCanvas(event.target)) {
        event.preventDefault();
        if (isMacContextClick(event)) latest.current({ clientX: event.clientX, clientY: event.clientY });
        return;
      }
      // The context-menu key, which the keyboard shortcuts of the graph answer, reports the left
      // button: the menu of the browser does not open over the one of the graph, out of the fields.
      if (event.button === 0 && !isMacContextClick(event) && !isEditable(event.target)) event.preventDefault();
    };
    container.addEventListener('mousedown', onDown, true);
    document.addEventListener('mouseup', onUp, true);
    container.addEventListener('contextmenu', onContextMenu);
    return () => {
      container.removeEventListener('mousedown', onDown, true);
      document.removeEventListener('mouseup', onUp, true);
      container.removeEventListener('contextmenu', onContextMenu);
    };
  }, [containerRef, enabled]);
};

export default useGraphContextMenuGesture;
