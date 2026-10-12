const scrolls = (overflow: string) => overflow === 'auto' || overflow === 'scroll';

// A scroll container clips both axes, whichever one declared the overflow: the matrix columns box sets
// only `overflow-x: auto` but has a fixed height, so its rows scroll vertically even when its columns fit.
const isScroller = (element: HTMLElement) => {
  const { overflowX, overflowY } = window.getComputedStyle(element);
  if (!scrolls(overflowX) && !scrolls(overflowY)) return false;
  return element.scrollWidth > element.clientWidth || element.scrollHeight > element.clientHeight;
};

// Lets the export wrapper grow to its whole content for the duration of a capture, so no column or row is
// cropped. The wrapper becomes `width: max-content`. The matrix sits in a viewport-sized scroll box, which
// would still clip it: every scroller inside the wrapper is opened on both axes too.
// Returns the function that puts every touched element back to its previous inline style.
const prepareMatrixCapture = (wrapper: HTMLElement): (() => void) => {
  // Measure first: opening one scroller must not change what the next one reports.
  const scrollers = Array.from(wrapper.querySelectorAll<HTMLElement>('*')).filter(isScroller);
  const touched = [wrapper, ...scrollers].map((element) => ({ element, style: element.getAttribute('style') }));

  const widths = scrollers.map((element) => Math.max(element.scrollWidth, element.clientWidth));
  scrollers.forEach((element, index) => {
    element.style.width = `${widths[index]}px`;
    element.style.height = 'auto';
    element.style.overflow = 'visible';
  });
  wrapper.style.width = 'max-content';
  wrapper.style.height = 'auto';

  return () => {
    touched.forEach(({ element, style }) => {
      if (style === null) element.removeAttribute('style');
      else element.setAttribute('style', style);
    });
  };
};

export default prepareMatrixCapture;
