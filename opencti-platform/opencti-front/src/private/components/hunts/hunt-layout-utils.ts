import type { CSSProperties } from 'react';

/**
 * Top of the element in the viewport when none of its scrolling ancestors is scrolled.
 * The page scrolls in the main content box, not the window, so window.scrollY alone stays 0.
 */
export const unscrolledTop = (element: HTMLElement) => {
  let top = element.getBoundingClientRect().top;
  for (let parent = element.parentElement; parent; parent = parent.parentElement) {
    top += parent.scrollTop;
  }
  return top;
};

/**
 * The `DialogBody` of a design-system dialog scrolls, so it clips what overflows it, and the library fields paint
 * their focus ring 4px outside their box: the body gives the ring that room and takes it back from the layout, so the
 * fields keep the width of the title and the footer. See fds-migration/MIGRATION-DECISIONS.md#dialog-padding-keys
 */
export const HUNT_DIALOG_BODY_STYLE: CSSProperties = { margin: 'calc(var(--spacing) * -1)', padding: 'var(--spacing)' };
