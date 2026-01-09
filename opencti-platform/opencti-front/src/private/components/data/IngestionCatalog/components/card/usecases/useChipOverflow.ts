import { useState, useRef, useEffect, useCallback } from 'react';
import useDebounceCallback from '../../../../../../../utils/hooks/useDebounceCallback';

const GAP = 8;
const MIN_CHIP_WIDTH = 60;

const useChipOverflow = (items: string[]) => {
  const [visibleCount, setVisibleCount] = useState(items.length);
  const containerRef = useRef<HTMLDivElement>(null);
  const chipRefs = useRef<(HTMLElement | null)[]>([]);
  const overflowChipRef = useRef<HTMLElement | null>(null);

  const calculateVisibleCount = useCallback(() => {
    if (!containerRef.current) return;

    const containerWidth = containerRef.current.offsetWidth;

    let usedWidth = 0;
    let visibleChips = 0;

    for (let i = 0; i < chipRefs.current.length; i++) {
      const chip = chipRefs.current[i];
      if (!chip) continue;

      const chipWidth = chip.offsetWidth;
      const gapBeforeChip = i > 0 ? GAP : 0;
      const widthNeeded = usedWidth + gapBeforeChip + chipWidth;

      // Does this chip fit completely?
      if (widthNeeded <= containerWidth) {
        usedWidth = widthNeeded;
        visibleChips++;
        continue;
      }

      // Chip doesn't fit completely
      const spaceLeft = containerWidth - usedWidth - gapBeforeChip;
      const isLastChip = (i === items.length - 1);
      const chipsStillHidden = items.length - visibleChips;

      // Show with ellipsis if: last chip OR only 1 would be hidden
      const shouldShowWithEllipsis
        = (isLastChip || chipsStillHidden === 1) && spaceLeft >= MIN_CHIP_WIDTH;

      if (shouldShowWithEllipsis) {
        visibleChips++;
      }

      break;
    }

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
