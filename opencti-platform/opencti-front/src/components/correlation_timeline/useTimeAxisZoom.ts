import { RefObject, useEffect, useRef, useState } from 'react';

const DAY = 24 * 60 * 60 * 1000;
// Do not let the time window collapse below a day, there is nothing to see.
const MIN_SPAN = DAY;

interface UseTimeAxisZoomArgs {
  // Element capturing the wheel events, usually the chart wrapper.
  ref: RefObject<HTMLElement | null>;
  // Full extent of the data, as timestamps.
  fullExtent: [number, number];
  plotStart: number;
  plotEnd: number;
}

/**
 * Zoom and pan restricted to the time axis. The vertical axis of these charts
 * is a list of rows, not a continuous dimension, so scaling it would only
 * stretch labels.
 *
 * Plain vertical wheel is deliberately left alone so that a tall chart still
 * lets the page scroll. Pinch (browsers report it as ctrlKey) and Ctrl/Cmd +
 * wheel zoom around the cursor; a horizontal two-finger swipe pans.
 */
const useTimeAxisZoom = ({
  ref,
  fullExtent,
  plotStart,
  plotEnd,
}: UseTimeAxisZoomArgs) => {
  // `null` means "everything", so a data change resets the view naturally.
  const [timeWindow, setTimeWindow] = useState<[number, number] | null>(null);
  const domain = timeWindow ?? fullExtent;

  // The listener is attached imperatively, so it needs the live values.
  const domainRef = useRef(domain);
  domainRef.current = domain;
  const extentRef = useRef(fullExtent);
  extentRef.current = fullExtent;
  const plotRef = useRef({ plotStart, plotEnd });
  plotRef.current = { plotStart, plotEnd };

  useEffect(() => {
    const element = ref.current;
    if (!element) return undefined;
    const onWheel = (event: WheelEvent) => {
      const [start, end] = domainRef.current;
      const [minBound, maxBound] = extentRef.current;
      const { plotStart: from, plotEnd: to } = plotRef.current;
      const span = end - start;
      const isZoom = event.ctrlKey || event.metaKey;
      const isPan = !isZoom && Math.abs(event.deltaX) > Math.abs(event.deltaY);
      if (!isZoom && !isPan) return; // let the page scroll
      event.preventDefault();

      if (isZoom) {
        const rect = element.getBoundingClientRect();
        const x = Math.min(Math.max(event.clientX - rect.left, from), to);
        const anchor = start + ((x - from) / (to - from)) * span;
        const factor = Math.exp(event.deltaY * 0.002);
        const nextSpan = Math.min(Math.max(span * factor, MIN_SPAN), maxBound - minBound);
        // Keep the instant under the cursor pinned while the span changes.
        const ratio = (anchor - start) / span;
        let nextStart = anchor - ratio * nextSpan;
        let nextEnd = nextStart + nextSpan;
        if (nextStart < minBound) { nextStart = minBound; nextEnd = minBound + nextSpan; }
        if (nextEnd > maxBound) { nextEnd = maxBound; nextStart = maxBound - nextSpan; }
        setTimeWindow(nextSpan >= maxBound - minBound ? null : [nextStart, nextEnd]);
        return;
      }

      const shift = (event.deltaX / (to - from)) * span;
      let nextStart = start + shift;
      let nextEnd = end + shift;
      if (nextStart < minBound) { nextStart = minBound; nextEnd = minBound + span; }
      if (nextEnd > maxBound) { nextEnd = maxBound; nextStart = maxBound - span; }
      setTimeWindow([nextStart, nextEnd]);
    };
    // Non-passive: preventDefault is refused on passive listeners.
    element.addEventListener('wheel', onWheel, { passive: false });
    return () => element.removeEventListener('wheel', onWheel);
  }, [ref]);

  return {
    domain,
    isZoomed: timeWindow !== null,
    resetZoom: () => setTimeWindow(null),
  };
};

export default useTimeAxisZoom;
