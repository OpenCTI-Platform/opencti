import { useState, useRef, useEffect, useCallback } from 'react';
import useDebounceCallback from '../../../../../../../utils/hooks/useDebounceCallback';

const GAP = 8;
const MIN_CHIP_WIDTH = 60;

const useChipOverflow = (items: string[] | null | undefined = []) => {
  const currentItems = items ?? [];

  const [visibleCount, setVisibleCount] = useState(currentItems.length);
  const chipRefs = useRef<(HTMLElement | null)[]>([]);
  const [containerElement, setContainerElement] = useState<HTMLDivElement | null>(null);

  const containerRef = useCallback((node: HTMLDivElement | null) => {
    if (node !== null) {
      setContainerElement(node);
    }
  }, []);

  const calculateVisibleCount = useCallback(() => {
    if (!containerElement || currentItems.length === 0) return;

    const containerWidth = containerElement.offsetWidth;

    let usedWidth = 0;
    let visibleChips = 0;

    const validChips = chipRefs.current.filter((chip) => chip !== null);

    if (validChips.length === 0) return;

    for (let i = 0; i < validChips.length; i++) {
      const chip = validChips[i];

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

      // Show with ellipsis if there's at least MIN_CHIP_WIDTH space
      if (spaceLeft >= MIN_CHIP_WIDTH) {
        visibleChips++;
      }

      break;
    }

    setVisibleCount(Math.max(1, visibleChips));
  }, [containerElement, currentItems.length]);

  const debouncedCalculate = useDebounceCallback(calculateVisibleCount, 150);

  useEffect(() => {
    if (containerElement) {
      calculateVisibleCount();
    }
  }, [containerElement, currentItems, calculateVisibleCount]);

  useEffect(() => {
    if (!containerElement) return;

    const observer = new ResizeObserver(() => {
      debouncedCalculate();
    });

    observer.observe(containerElement);
    calculateVisibleCount();

    return () => {
      observer.disconnect();
    };
  }, [containerElement, calculateVisibleCount, debouncedCalculate]);

  return {
    containerRef,
    chipRefs,
    visibleCount,
    shouldTruncate: visibleCount < currentItems.length,
  };
};

export default useChipOverflow;
