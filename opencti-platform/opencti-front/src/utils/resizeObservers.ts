/**
 * Observe a DOM element and call the callback function each time
 * the element has been resized.
 *
 * Don't forget to stop observing when not needed anymore.
 * const observer = callbackResizeObserver(...);
 * observer.disconnect();
 *
 * @param target The element to observe.
 * @param callback The callback to execute on resize.
 * @returns The observer.
 */
const callbackResizeObserver = (target: Element, callback: (entry: Element) => void) => {
  const observer = new ResizeObserver((entries) => {
    entries.forEach((entry) => callback(entry.target));
  });
  observer.observe(target);
  return observer;
};

export default callbackResizeObserver;
