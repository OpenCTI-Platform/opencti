// Keyboard helpers shared by the graph shortcuts and the global search shortcut.

export const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent);

/** The key goes to a field being typed in: a shortcut made of a bare key must leave it alone. */
export const isEditable = (target: EventTarget | null) => {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName);
};

const OVERLAY_SELECTOR = '.MuiDialog-root, .MuiDrawer-modal, .MuiPopover-root, [role="dialog"][aria-modal="true"], [role="menu"]';
const HIDDEN_SELECTOR = '.MuiModal-hidden, [aria-hidden="true"], [hidden]';

/**
 * A dialog, drawer or menu open over the page owns the keyboard. Overlays kept mounted while
 * closed (`keepMounted`, for example the export loader of the container header) do not count.
 */
export const isOverlayOpen = (root: ParentNode = document) => Array.from(root.querySelectorAll(OVERLAY_SELECTOR))
  .some((overlay) => !overlay.closest(HIDDEN_SELECTOR));
