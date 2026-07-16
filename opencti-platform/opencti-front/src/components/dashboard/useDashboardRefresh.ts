import { useCallback, useEffect, useRef, useState, useTransition } from 'react';

interface UseDashboardRefreshOptions {
  initialRefreshRateSeconds?: number;
  onRefreshRateChange?: (refreshRateInSeconds: number) => void;
}

interface UseDashboardRefreshResult {
  localRefreshRateSeconds: number;
  refreshRate: number | null;
  refreshToken: number;
  isAutoRefreshing: boolean;
  handleManualRefresh: () => void;
  handleRefreshRateChange: (refreshRateInSeconds: number) => void;
}

const useDashboardRefresh = ({
  initialRefreshRateSeconds = 0,
  onRefreshRateChange,
}: UseDashboardRefreshOptions): UseDashboardRefreshResult => {
  const [localRefreshRateSeconds, setLocalRefreshRateSeconds] = useState<number>(initialRefreshRateSeconds);
  const refreshRate = localRefreshRateSeconds ? localRefreshRateSeconds * 1000 : null;

  const [lastRefreshTime, setLastRefreshTime] = useState(new Date());
  const previousInitialRefreshRateRef = useRef(initialRefreshRateSeconds);
  // Timestamp of the last refresh that actually fired (manual, auto, rate change
  // or external sync). Kept in a ref so auto ticks can update it without
  // re-running the scheduling effect, while still letting the visibility handler
  // compute how much time is left before the next tick.
  const lastRefreshAtRef = useRef(Date.now());
  // Keep local state aligned with external workspace updates without overriding local edits on every render.
  useEffect(() => {
    if (previousInitialRefreshRateRef.current === initialRefreshRateSeconds) return;
    previousInitialRefreshRateRef.current = initialRefreshRateSeconds;
    setLocalRefreshRateSeconds(initialRefreshRateSeconds);
    lastRefreshAtRef.current = Date.now();
    setLastRefreshTime(new Date());
  }, [initialRefreshRateSeconds]);

  const [refreshToken, setRefreshToken] = useState(0);
  const [isAutoRefreshing, setIsAutoRefreshing] = useState(false);
  const [, startTransition] = useTransition();

  const handleManualRefresh = useCallback(() => {
    lastRefreshAtRef.current = Date.now();
    setLastRefreshTime(new Date());
    // Mark the refresh cascade as a non-urgent transition so React can paint the
    // button's disabled state first and refetch widgets without a long blocking task.
    startTransition(() => {
      setRefreshToken((prev) => prev + 1);
    });
  }, []);

  const handleRefreshRateChange = useCallback((refreshRateInSeconds: number) => {
    setLocalRefreshRateSeconds(refreshRateInSeconds);
    lastRefreshAtRef.current = Date.now();
    setLastRefreshTime(new Date());
    onRefreshRateChange?.(refreshRateInSeconds);
  }, [onRefreshRateChange]);

  useEffect(() => {
    if (!refreshRate) {
      return undefined;
    }

    let resetSpinnerTimeout: ReturnType<typeof setTimeout> | null = null;
    let timeout: ReturnType<typeof setTimeout> | null = null;
    let interval: ReturnType<typeof setInterval> | null = null;

    const clearTimers = () => {
      if (timeout !== null) {
        clearTimeout(timeout);
        timeout = null;
      }
      if (interval !== null) {
        clearInterval(interval);
        interval = null;
      }
    };

    const triggerAutoRefresh = () => {
      lastRefreshAtRef.current = Date.now();
      setIsAutoRefreshing(true);
      startTransition(() => {
        setRefreshToken((prev) => prev + 1);
      });

      if (resetSpinnerTimeout) {
        clearTimeout(resetSpinnerTimeout);
      }
      resetSpinnerTimeout = setTimeout(() => {
        setIsAutoRefreshing(false);
      }, 1200);
    };

    // Schedule the next auto-refresh based on the time already elapsed since the
    // last refresh. When the tab was hidden longer than a full interval the delay
    // clamps to 0, producing a single immediate catch-up refresh; otherwise it
    // resumes with exactly the remaining time (no spurious refetch on brief
    // tab switches).
    const scheduleNextRefresh = () => {
      clearTimers();
      const msUntilNextTick = Math.max(0, refreshRate - (Date.now() - lastRefreshAtRef.current));
      timeout = setTimeout(() => {
        triggerAutoRefresh();
        interval = setInterval(() => {
          triggerAutoRefresh();
        }, refreshRate);
      }, msUntilNextTick);
    };

    // Pause polling while the tab is hidden and reschedule (with catch-up) when
    // it becomes visible again, so background tabs stop hitting the API.
    const handleVisibilityChange = () => {
      if (document.hidden) {
        clearTimers();
      } else {
        scheduleNextRefresh();
      }
    };

    if (!document.hidden) {
      scheduleNextRefresh();
    }
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      clearTimers();
      if (resetSpinnerTimeout !== null) {
        clearTimeout(resetSpinnerTimeout);
      }
      setIsAutoRefreshing(false);
    };
  }, [refreshRate, lastRefreshTime]);

  return {
    localRefreshRateSeconds,
    refreshRate,
    refreshToken,
    isAutoRefreshing,
    handleManualRefresh,
    handleRefreshRateChange,
  };
};

export default useDashboardRefresh;
