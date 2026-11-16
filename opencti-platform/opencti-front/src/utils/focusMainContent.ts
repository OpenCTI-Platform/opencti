type ClickModifiers = Partial<Pick<MouseEvent, 'metaKey' | 'ctrlKey' | 'shiftKey' | 'altKey'>>;

/**
 * Moves the focus to the page content (`<main>`, focusable with tabIndex -1), so the next Tab reaches the first control
 * of the page. For navigations triggered from a control that keeps the focus (the pages search): `<main>` outlives the
 * route change, so there is nothing to wait for. A click with a modifier opens a new tab: the current page stays.
 */
export const focusMainContent = (event?: ClickModifiers): void => {
  if (event?.metaKey || event?.ctrlKey || event?.shiftKey || event?.altKey) return;
  document.querySelector<HTMLElement>('main')?.focus({ preventScroll: true });
};
