import { useEffect, useRef, useState } from 'react';

// Progressive mounting for large client-side card grids, aligned with the
// platform's infinite-scroll card lists: only the first batches are in the
// DOM, and more cards are revealed as the sentinel approaches the viewport.
const useProgressiveReveal = (totalCount: number, resetKey: string, batchSize = 24) => {
  const [visibleCount, setVisibleCount] = useState(batchSize);
  const sentinelRef = useRef<HTMLDivElement | null>(null);

  // Any filter/sort change re-starts from the first batch.
  useEffect(() => {
    setVisibleCount(batchSize);
  }, [resetKey, batchSize]);

  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel || visibleCount >= totalCount) return undefined;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setVisibleCount((current) => Math.min(current + batchSize, totalCount));
        }
      },
      // Start mounting the next batch well before the user reaches the end.
      { rootMargin: '600px' },
    );
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, [visibleCount, totalCount, batchSize]);

  return { visibleCount, sentinelRef, hasMore: visibleCount < totalCount };
};

export default useProgressiveReveal;
