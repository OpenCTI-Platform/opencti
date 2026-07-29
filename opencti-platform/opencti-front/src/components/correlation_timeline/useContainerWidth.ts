import { useEffect, useRef, useState } from 'react';

/**
 * Measures the rendered width of a wrapper element, so that an SVG chart can
 * lay itself out in real pixels instead of relying on a viewBox that would
 * scale text along with the geometry.
 */
const useContainerWidth = (fallback = 1000) => {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(fallback);
  useEffect(() => {
    const element = ref.current;
    if (!element) return undefined;
    const observer = new ResizeObserver((entries) => {
      const observed = entries[0]?.contentRect.width;
      if (observed && observed > 0) setWidth(observed);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return { ref, width };
};

export default useContainerWidth;
