import { useState, useRef, useEffect, useCallback } from 'react';
import useDebounceCallback from '../../../../../../../utils/hooks/useDebounceCallback';

const GAP = 8;
// Below this width a truncated chip is unreadable: show the +N chip instead.
const MIN_CHIP_WIDTH = 110;
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

      // The last chip may shrink with an ellipsis while it stays readable;
      // otherwise it is folded into the +N overflow chip (full values are
      // exposed through its tooltip).
      const shouldShowWithEllipsis = isLastChip && spaceLeft >= MIN_CHIP_WIDTH;

      if (shouldShowWithEllipsis) {
        visibleChips++;
      } else if (spaceLeft < OVERFLOW_CHIP_WIDTH && visibleChips > 1) {
        // Free up room so the +N chip itself is never clipped.
        visibleChips--;
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
