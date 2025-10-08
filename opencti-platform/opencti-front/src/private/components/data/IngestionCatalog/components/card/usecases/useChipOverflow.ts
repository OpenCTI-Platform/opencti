import { useRef, useState, useEffect } from 'react';

const useChipOverflow = (useCases: string[]) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const chipRefs = useRef<(HTMLDivElement | null)[]>([]);
  const [visibleCount, setVisibleCount] = useState(useCases.length);
  const [shouldTruncate, setShouldTruncate] = useState(false);
  const resizeTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    chipRefs.current = chipRefs.current.slice(0, useCases.length);
  }, [useCases.length]);

  useEffect(() => {
    const calculateVisibleChips = () => {
      if (!containerRef.current) return;

      const containerWidth = containerRef.current.offsetWidth;
      const validChips = chipRefs.current.filter((ref) => ref !== null);

      if (validChips.length === 0) return;

      const GAP_WIDTH = 8;
      const PLUS_CHIP_WIDTH = 70;
      const MIN_CHIP_WIDTH = 60; // Minimum width before collapsing to +N
      const TRUNCATION_BUFFER = 20; // Extra buffer to decide when to truncate

      let accumulatedWidth = 0;
      let visibleChips = 0;
      let needsTruncation = false;

      for (let i = 0; i < validChips.length; i += 1) {
        const chip = validChips[i];
        if (!chip) return;

        const chipWidth = chip.offsetWidth;
        const gapWidth = visibleChips > 0 ? GAP_WIDTH : 0;
        const totalWidthWithThisChip = accumulatedWidth + chipWidth + gapWidth;

        const hasMoreChips = i < validChips.length - 1;
        const widthNeeded = hasMoreChips
          ? totalWidthWithThisChip + GAP_WIDTH + PLUS_CHIP_WIDTH
          : totalWidthWithThisChip;

        // Can fit at full width
        if (widthNeeded <= containerWidth) {
          accumulatedWidth = totalWidthWithThisChip;
          visibleChips += 1;
          needsTruncation = false;
        } else {
          // Check if we can fit this chip with truncation
          const minWidthNeeded = hasMoreChips
            ? accumulatedWidth + MIN_CHIP_WIDTH + gapWidth + GAP_WIDTH + PLUS_CHIP_WIDTH
            : accumulatedWidth + MIN_CHIP_WIDTH + gapWidth;

          // Check with buffer: if we're close to needing truncation, apply it
          const truncatedWidthNeeded = hasMoreChips
            ? accumulatedWidth + MIN_CHIP_WIDTH + TRUNCATION_BUFFER + gapWidth + GAP_WIDTH + PLUS_CHIP_WIDTH
            : accumulatedWidth + MIN_CHIP_WIDTH + TRUNCATION_BUFFER + gapWidth;

          if (minWidthNeeded <= containerWidth && truncatedWidthNeeded > containerWidth) {
            needsTruncation = true;
            visibleChips += 1;
            break;
          } else if (minWidthNeeded <= containerWidth) {
            visibleChips += 1;
            needsTruncation = false;
          }
          break;
        }
      }

      const newVisibleCount = Math.max(1, visibleChips);

      setVisibleCount((prev) => {
        if (prev !== newVisibleCount) {
          setShouldTruncate(false); // Reset truncation when count changes
          return newVisibleCount;
        }
        return prev;
      });

      setShouldTruncate(needsTruncation);
    };

    const handleResize = () => {
      if (resizeTimeoutRef.current) {
        clearTimeout(resizeTimeoutRef.current);
      }
      resizeTimeoutRef.current = setTimeout(calculateVisibleChips, 100);
    };

    const initialTimer = setTimeout(calculateVisibleChips, 50);
    window.addEventListener('resize', handleResize);

    return () => {
      clearTimeout(initialTimer);
      if (resizeTimeoutRef.current) {
        clearTimeout(resizeTimeoutRef.current);
      }
      window.removeEventListener('resize', handleResize);
    };
  }, [useCases]);

  return { containerRef, chipRefs, visibleCount, shouldTruncate };
};

export default useChipOverflow;
