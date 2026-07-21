import { useState, useRef, useEffect, useCallback } from 'react';
import useDebounceCallback from '../../../../../../../utils/hooks/useDebounceCallback';

const GAP = 8;
// Approximate width of the "+N" overflow chip, reserved so it never gets
// clipped by the container overflow.
const OVERFLOW_CHIP_WIDTH = 48;

const useChipOverflow = (items: string[]) => {
  const [visibleCount, setVisibleCount] = useState(items.length);
  const containerRef = useRef<HTMLDivElement>(null);
  const chipRefs = useRef<(HTMLElement | null)[]>([]);
  const overflowChipRef = useRef<HTMLElement | null>(null);

  const calculateVisibleCount = useCallback(() => {
    if (!containerRef.current) return;

    const containerWidth = containerRef.current.offsetWidth;
    const widths = chipRefs.current
      .slice(0, items.length)
      .map((chip) => chip?.offsetWidth ?? 0);
    const totalWidth = widths.reduce((acc, width, index) => acc + width + (index > 0 ? GAP : 0), 0);

    // Everything fits: no overflow chip needed.
    if (totalWidth <= containerWidth) {
      setVisibleCount(items.length);
      return;
    }

    // Otherwise the +N chip is displayed: reserve its room first so it can
    // never be clipped, then fit as many full chips as possible before it.
    const available = containerWidth - GAP - OVERFLOW_CHIP_WIDTH;
    let usedWidth = 0;
    let visibleChips = 0;
    for (let i = 0; i < widths.length; i++) {
      const widthNeeded = usedWidth + (i > 0 ? GAP : 0) + widths[i];
      if (widthNeeded > available) break;
      usedWidth = widthNeeded;
      visibleChips++;
    }

    // Always keep the first chip: when even the reserved space is too narrow
    // it shrinks with an ellipsis (full values stay in the tooltips).
    setVisibleCount(Math.max(1, visibleChips));
  }, [items.length]);

  const debouncedCalculate = useDebounceCallback(calculateVisibleCount, 150);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver(() => {
      debouncedCalculate();
    });

    observer.observe(container);
    calculateVisibleCount();

    return () => {
      observer.disconnect();
    };
  }, [calculateVisibleCount, debouncedCalculate]);

  return {
    containerRef,
    chipRefs,
    overflowChipRef,
    visibleCount,
    shouldTruncate: visibleCount < items.length,
  };
};

export default useChipOverflow;
