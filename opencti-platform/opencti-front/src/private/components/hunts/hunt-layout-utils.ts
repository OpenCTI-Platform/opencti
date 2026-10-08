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
