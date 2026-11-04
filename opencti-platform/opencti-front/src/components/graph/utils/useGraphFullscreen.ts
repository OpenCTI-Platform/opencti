import { MutableRefObject, useCallback, useEffect, useRef } from 'react';

/**
 * Above the application bars and the navigation (MUI app bar 1100, drawer 1200) and below every
 * MUI modal, menu and snackbar (1300 and above): the dialogs the graph opens (relationship
 * creation, expansion, edition, removal) are portalled to the document body and must stay on top.
 */
const OVERLAY_Z_INDEX = 1250;

/**
 * Full screen for a graph: its container is laid over the whole window and the browser goes full
 * screen on the document, so the dialogs the graph opens, rendered outside the container, still
 * show. Leaving with Escape or the browser control restores the container as it was. The container
 * is the parent the graph sizes its canvases from: laid over the window, the canvases follow it.
 */
const useGraphFullscreen = (
  parentRef: MutableRefObject<HTMLElement | null>,
  isFullscreen: boolean,
  setIsFullscreen: (value: boolean) => void,
  background: string,
) => {
  const savedStyle = useRef<string | null>(null);
  /** Whether the document full screen was requested by this graph, and so is its to leave. */
  const ownsDocumentFullscreen = useRef(false);

  const leaveDocumentFullscreen = useCallback(() => {
    const owned = ownsDocumentFullscreen.current;
    ownsDocumentFullscreen.current = false;
    if (owned && document.fullscreenElement) {
      document.exitFullscreen().catch(() => {
        // Already left by the browser itself.
      });
    }
  }, []);

  const restore = useCallback(() => {
    const container = parentRef.current;
    if (container && savedStyle.current !== null) {
      container.style.cssText = savedStyle.current;
    }
    savedStyle.current = null;
  }, [parentRef]);

  const enter = useCallback(() => {
    const container = parentRef.current;
    if (!container) return;
    savedStyle.current = container.style.cssText;
    Object.assign(container.style, {
      position: 'fixed',
      inset: '0',
      width: '100vw',
      height: '100vh',
      margin: '0',
      zIndex: String(OVERLAY_Z_INDEX),
      background,
    });
    setIsFullscreen(true);
    if (document.fullscreenEnabled && !document.fullscreenElement) {
      ownsDocumentFullscreen.current = true;
      document.documentElement.requestFullscreen().then(() => {
        // Left (exit or another page) while the browser was still entering: leave now that it has.
        if (!ownsDocumentFullscreen.current && document.fullscreenElement) {
          document.exitFullscreen().catch(() => {
            // Already left by the browser itself.
          });
        }
      }).catch(() => {
        // Refused by the browser (for example outside a user gesture): the overlay alone is kept.
        ownsDocumentFullscreen.current = false;
      });
    }
  }, [parentRef, background, setIsFullscreen]);

  const exit = useCallback(() => {
    restore();
    setIsFullscreen(false);
    leaveDocumentFullscreen();
  }, [restore, setIsFullscreen, leaveDocumentFullscreen]);

  const toggle = useCallback(() => {
    if (isFullscreen) exit();
    else enter();
  }, [isFullscreen, enter, exit]);

  useEffect(() => {
    const onChange = () => {
      if (!document.fullscreenElement && savedStyle.current !== null) {
        ownsDocumentFullscreen.current = false;
        restore();
        setIsFullscreen(false);
      }
    };
    document.addEventListener('fullscreenchange', onChange);
    return () => document.removeEventListener('fullscreenchange', onChange);
  }, [restore, setIsFullscreen]);

  // Leaving the page while in full screen gives the container back its own style and the browser
  // leaves the full screen the graph asked for, so the next page does not open in it.
  useEffect(() => () => {
    restore();
    leaveDocumentFullscreen();
  }, [restore, leaveDocumentFullscreen]);

  return { toggle, exit };
};

export default useGraphFullscreen;
