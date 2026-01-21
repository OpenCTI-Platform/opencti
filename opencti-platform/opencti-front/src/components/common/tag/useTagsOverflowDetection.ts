import { useEffect, useRef, useState } from 'react';

interface UseTagsOverflowDetectionOptions {
  totalCount: number;
  gapPx: number;
  direction?: 'ltr' | 'rtl';
}

interface UseTagsOverflowDetectionResult {
  measureContainerRef: React.RefObject<HTMLDivElement | null>;
  visibleContainerRef: React.RefObject<HTMLDivElement | null>;
  visibleCount: number;
  overflowCount: number;
  isRTL: boolean;
}

/**
 * Custom hook for detecting overflow in tag containers
 * Measures tags in a hidden container and determines how many can fit in the visible container
 */
export function useTagsOverflowDetection({
  totalCount,
  gapPx,
  direction = 'ltr',
}: UseTagsOverflowDetectionOptions): UseTagsOverflowDetectionResult {
  const [visibleCount, setVisibleCount] = useState(totalCount);
  const measureContainerRef = useRef<HTMLDivElement>(null);
  const visibleContainerRef = useRef<HTMLDivElement>(null);

  const isRTL = direction === 'rtl';
  const overflowCount = totalCount - visibleCount;

  useEffect(() => {
    const measureContainer = measureContainerRef.current;
    const visibleContainer = visibleContainerRef.current;

    if (!measureContainer || !visibleContainer || totalCount === 0) {
      setVisibleCount(totalCount);
      return;
    }

    const checkOverflow = () => {
      const containerWidth = visibleContainer.offsetWidth;

      // Early exit if container has no width yet
      if (containerWidth === 0) {
        return;
      }

      // Get all tag elements from the measure container
      const tagElements = Array.from(
        measureContainer.querySelectorAll('[data-tag-item]'),
      ) as HTMLElement[];

      if (tagElements.length === 0) {
        return;
      }

      // Get the overflow indicator width
      const overflowIndicator = measureContainer.querySelector(
        '[data-overflow-tag]',
      ) as HTMLElement;
      const overflowWidth = overflowIndicator ? overflowIndicator.offsetWidth : 0;

      // Get the trailing content (button) width
      const trailingElement = measureContainer.querySelector(
        '[data-trailing-content]',
      ) as HTMLElement;
      const trailingWidth = trailingElement ? trailingElement.offsetWidth : 0;

      let accumulatedWidth = 0;
      let count = 0;
      const gapWidth = gapPx;

      // Start with trailing content width (if present)
      const baseWidth = trailingWidth + (trailingWidth > 0 ? gapWidth : 0);

      for (let i = 0; i < tagElements.length; i++) {
        const tagWidth = tagElements[i].offsetWidth;

        // Skip if tag hasn't rendered yet
        if (tagWidth === 0) {
          continue;
        }

        const neededWidth = baseWidth + accumulatedWidth + tagWidth + (i > 0 ? gapWidth : 0);

        // Check if we have room for this tag AND the overflow indicator (if needed)
        const remainingTags = tagElements.length - (i + 1);
        const needsOverflow = remainingTags > 0;
        const totalNeededWidth = needsOverflow
          ? neededWidth + gapWidth + overflowWidth
          : neededWidth;

        if (totalNeededWidth <= containerWidth) {
          count++;
          accumulatedWidth += tagWidth + (i > 0 ? gapWidth : 0);
        } else {
          break;
        }
      }

      // Ensure at least one tag is visible if there's any space
      if (count === 0 && tagElements.length > 0 && containerWidth > 0) {
        count = 1;
      }

      setVisibleCount(count);
    };

    // Use setTimeout to ensure DOM is fully rendered before measuring
    const timeoutId = setTimeout(checkOverflow, 0);

    // Observe container resize
    const resizeObserver = new ResizeObserver(() => {
      checkOverflow();
    });

    resizeObserver.observe(visibleContainer);

    return () => {
      clearTimeout(timeoutId);
      resizeObserver.disconnect();
    };
  }, [totalCount, gapPx, direction]);

  return {
    measureContainerRef,
    visibleContainerRef,
    visibleCount,
    overflowCount,
    isRTL,
  };
}
