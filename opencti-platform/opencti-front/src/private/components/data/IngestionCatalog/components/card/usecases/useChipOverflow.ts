import { useState, useRef, useEffect } from 'react';

const GAP_WIDTH = 8;
const PLUS_CHIP_WIDTH = 70;

const useChipOverflow = (useCases: string[]) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const chipRefs = useRef<(HTMLDivElement | null)[]>([]);
  const [visibleCount, setVisibleCount] = useState(useCases.length);
  const [shouldTruncate, setShouldTruncate] = useState(false);

  useEffect(() => {
    chipRefs.current = chipRefs.current.slice(0, useCases.length);
  }, [useCases.length]);

  useEffect(() => {
    let resizeTimeout: ReturnType<typeof setTimeout>;

    const calculateVisibleChips = () => {
      const container = containerRef.current;
      if (!container) return;

      const containerWidth = container.offsetWidth;
      const chips = chipRefs.current.filter(Boolean) as HTMLDivElement[];

      if (chips.length === 0) return;

      let accumulatedWidth = 0;
      let count = 0;
      let truncationNeeded = false;

      for (let i = 0; i < chips.length; i += 1) {
        const chipWidth = chips[i].offsetWidth;
        const hasMore = i < chips.length - 1;
        const gap = count > 0 ? GAP_WIDTH : 0;
        const widthWithChip = accumulatedWidth + chipWidth + gap;

        // If we can still fit the chip and possibly the +N indicator
        const remainingSpace = containerWidth - widthWithChip;
        const spaceNeededForRest = hasMore ? PLUS_CHIP_WIDTH + GAP_WIDTH : 0;

        if (remainingSpace >= spaceNeededForRest) {
          accumulatedWidth = widthWithChip;
          count += 1;
        } else {
          truncationNeeded = true;
          break;
        }
      }

      setVisibleCount(Math.max(1, count));
      setShouldTruncate(truncationNeeded);
    };

    const handleResize = () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(calculateVisibleChips, 100);
    };

    calculateVisibleChips();
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      clearTimeout(resizeTimeout);
    };
  }, [useCases]);

  return { containerRef, chipRefs, visibleCount, shouldTruncate };
};

export default useChipOverflow;
