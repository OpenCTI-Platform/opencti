import { type FocusEvent, type KeyboardEvent, type MutableRefObject, useEffect, useRef } from 'react';

const CONTROL_SELECTOR = 'button, input, [role="button"]';

/** The controls of a toolbar a reader can reach, in reading order: enabled and drawn. */
export const toolbarControls = (root: HTMLElement): HTMLElement[] => Array.from(root.querySelectorAll<HTMLElement>(CONTROL_SELECTOR))
  .filter((control) => !(control as HTMLButtonElement).disabled
    && control.getAttribute('aria-hidden') !== 'true'
    && !control.closest('[aria-hidden="true"], [hidden]'));

/** Where an arrow key, Home or End moves the focus from `index` among `count` controls, or `null`. */
export const nextToolbarIndex = (key: string, index: number, count: number): number | null => {
  if (count === 0) return null;
  switch (key) {
    case 'ArrowRight':
      return (index + 1) % count;
    case 'ArrowLeft':
      return (index - 1 + count) % count;
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    default:
      return null;
  }
};

/**
 * In a text field, the arrow keys first collapse a text selection, then move the caret until it
 * reaches the end it moves towards.
 */
export const keepsKeyInField = (target: EventTarget, key: string) => {
  if (!(target instanceof HTMLInputElement)) return false;
  if (key === 'Home' || key === 'End') return true;
  const { selectionStart, selectionEnd, value } = target;
  if (selectionStart === null || selectionEnd === null) return false;
  if (key !== 'ArrowLeft' && key !== 'ArrowRight') return false;
  if (selectionStart !== selectionEnd) return true;
  return key === 'ArrowLeft' ? selectionStart > 0 : selectionEnd < value.length;
};

/**
 * Makes a toolbar one tab stop: the arrow keys, Home and End move the focus between its controls,
 * and Tab leaves it from the last control used (WAI-ARIA toolbar pattern). Controls are found in
 * the DOM, so components rendering their own buttons in the toolbar take part.
 */
const useToolbarRovingFocus = (rootRef: MutableRefObject<HTMLElement | null>) => {
  const active = useRef<HTMLElement | null>(null);

  const applyTabStops = () => {
    const root = rootRef.current;
    if (!root) return;
    const controls = toolbarControls(root);
    if (!active.current || !controls.includes(active.current)) [active.current] = controls;
    Array.from(root.querySelectorAll<HTMLElement>(CONTROL_SELECTOR)).forEach((control) => {
      control.setAttribute('tabindex', control === active.current ? '0' : '-1');
    });
  };

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return undefined;
    applyTabStops();
    // Controls appear, disappear or get disabled with the selection and the graph state.
    const observer = new MutationObserver(applyTabStops);
    observer.observe(root, { childList: true, subtree: true, attributes: true, attributeFilter: ['disabled', 'hidden', 'aria-hidden'] });
    return () => observer.disconnect();
  }, [rootRef]);

  const onFocus = (event: FocusEvent<HTMLElement>) => {
    const root = rootRef.current;
    if (!root || !(event.target instanceof HTMLElement)) return;
    if (toolbarControls(root).includes(event.target) && active.current !== event.target) {
      active.current = event.target;
      applyTabStops();
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    const root = rootRef.current;
    if (!root || event.altKey || event.ctrlKey || event.metaKey) return;
    if (keepsKeyInField(event.target, event.key)) return;
    const controls = toolbarControls(root);
    const index = controls.indexOf(event.target as HTMLElement);
    if (index < 0) return;
    const next = nextToolbarIndex(event.key, index, controls.length);
    if (next === null) return;
    event.preventDefault();
    controls[next].focus();
  };

  return { onFocus, onKeyDown };
};

export default useToolbarRovingFocus;
