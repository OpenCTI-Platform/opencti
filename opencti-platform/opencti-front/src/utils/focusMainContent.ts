type ClickModifiers = Partial<Pick<MouseEvent, 'metaKey' | 'ctrlKey' | 'shiftKey' | 'altKey'>>;

/** Marks where the focus should land in a page: the next Tab goes to the control that follows it (see NavToolbarMenu). */
export const FOCUS_TARGET_ATTRIBUTE = 'data-focus-target';
const TARGET_SELECTOR = `[${FOCUS_TARGET_ATTRIBUTE}]`;
// Routes are lazy: the page, so its target, can show up after the navigation. Past this delay, we stop waiting.
const WAIT_FOR_TARGET_MS = 2000;

/**
 * Moves the focus into the page after a navigation triggered from a control that keeps it (the pages search):
 * to the page's `[data-focus-target]` if it has one, else to `<main>` (focusable with tabIndex -1), so the next Tab
 * reaches the first control of the page instead of the toolbar menu in front of it. `<main>` outlives the route change,
 * so it is focused right away; the target is then waited for, unless the user moved the focus elsewhere meanwhile.
 * A click with a modifier opens a new tab: the current page stays.
 */
export const focusMainContent = (event?: ClickModifiers): void => {
  if (event?.metaKey || event?.ctrlKey || event?.shiftKey || event?.altKey) return;
  const main = document.querySelector<HTMLElement>('main');
  if (!main) return;

  let focused: HTMLElement;
  const focus = (element: HTMLElement) => {
    focused = element;
    element.focus({ preventScroll: true });
  };
  focus(main.querySelector<HTMLElement>(TARGET_SELECTOR) ?? main);

  // The page being left can unmount the target we just focused (the focus falls back to the body): settle again.
  const settle = (): boolean => {
    const active = document.activeElement;
    if (active && active !== document.body && active !== focused) return false;
    const next = main.querySelector<HTMLElement>(TARGET_SELECTOR) ?? main;
    if (next !== active) focus(next);
    return true;
  };
  const observer = new MutationObserver(() => {
    if (!settle()) observer.disconnect();
  });
  observer.observe(main, { childList: true, subtree: true });
  setTimeout(() => observer.disconnect(), WAIT_FOR_TARGET_MS);
};
