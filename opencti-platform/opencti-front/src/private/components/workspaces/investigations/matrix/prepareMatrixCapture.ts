const isHorizontalScroller = (element: HTMLElement) => {
  const { overflowX } = window.getComputedStyle(element);
  return (overflowX === 'auto' || overflowX === 'scroll') && element.scrollWidth > element.clientWidth;
};

// Lets the export wrapper grow to its whole content for the duration of a capture, so no column is cropped.
// The wrapper becomes `width: max-content`. The matrix sits in a viewport-wide scroll box, which would still
// clip it: every horizontal scroller inside the wrapper is opened to its full width too.
// Returns the function that puts every touched element back to its previous inline style.
const prepareMatrixCapture = (wrapper: HTMLElement): (() => void) => {
  // Measure first: opening one scroller must not change what the next one reports.
  const scrollers = Array.from(wrapper.querySelectorAll<HTMLElement>('*')).filter(isHorizontalScroller);
  const touched = [wrapper, ...scrollers].map((element) => ({ element, style: element.getAttribute('style') }));

  const widths = scrollers.map((element) => element.scrollWidth);
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
