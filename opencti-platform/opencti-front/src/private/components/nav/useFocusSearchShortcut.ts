import { useEffect } from 'react';
import useSearchShortcut from '../../../utils/hooks/useSearchShortcut';
import { matchesSearchShortcut, SearchShortcut, TOP_BAR_SEARCH_ID } from '../../../utils/searchShortcut';
import { isEditable, isOverlayOpen } from '../../../utils/keyboard';

/**
 * Focuses the top bar search when the user presses their shortcut, from anywhere in the app.
 * Returns the shortcut so the field can announce it (placeholder, aria-keyshortcuts).
 */
const useFocusSearchShortcut = (): SearchShortcut | null => {
  const shortcut = useSearchShortcut();

  useEffect(() => {
    if (!shortcut) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      // `defaultPrevented`: someone closer to the key already answered it (the graph owns "/" while hovered).
      if (event.defaultPrevented || event.isComposing || event.keyCode === 229) return;
      if (!matchesSearchShortcut(event, shortcut)) return;
      // A bare key while typing is text. With Ctrl / Command it is a command, even in a field.
      if (isEditable(event.target) && !shortcut.ctrl && !shortcut.meta) return;
      // A dialog, drawer or menu owns the keyboard: the search behind it is out of reach.
      if (isOverlayOpen()) return;
      const field = document.getElementById(TOP_BAR_SEARCH_ID);
      if (!(field instanceof HTMLInputElement)) return;
      event.preventDefault();
      field.focus();
      field.select();
    };
    // On `window`, not `document`: it runs after the handlers registered on `document`, whatever their order.
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [shortcut]);

  return shortcut;
};

export default useFocusSearchShortcut;
