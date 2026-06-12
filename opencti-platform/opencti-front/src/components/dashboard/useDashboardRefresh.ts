import { useCallback, useEffect, useRef, useState } from 'react';

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

  // Keep local state aligned with external workspace updates without overriding local edits on every render.
  useEffect(() => {
    if (previousInitialRefreshRateRef.current === initialRefreshRateSeconds) return;
    previousInitialRefreshRateRef.current = initialRefreshRateSeconds;
    setLocalRefreshRateSeconds(initialRefreshRateSeconds);
    setLastRefreshTime(new Date());
  }, [initialRefreshRateSeconds]);

  const lastRefreshTimeRef = useRef(lastRefreshTime);
  useEffect(() => {
    lastRefreshTimeRef.current = lastRefreshTime;
  }, [lastRefreshTime]);

  const [refreshToken, setRefreshToken] = useState(0);
  const [isAutoRefreshing, setIsAutoRefreshing] = useState(false);

  const handleManualRefresh = useCallback(() => {
    setLastRefreshTime(new Date());
    setRefreshToken((prev) => prev + 1);
  }, []);

  const handleRefreshRateChange = useCallback((refreshRateInSeconds: number) => {
    setLocalRefreshRateSeconds(refreshRateInSeconds);
    setLastRefreshTime(new Date());
    onRefreshRateChange?.(refreshRateInSeconds);
  }, [onRefreshRateChange]);

  useEffect(() => {
    if (!refreshRate) return;

    let resetSpinnerTimeout: ReturnType<typeof setTimeout> | null = null;
    const triggerAutoRefresh = () => {
      setIsAutoRefreshing(true);
      setLastRefreshTime(new Date());
      setRefreshToken((prev) => prev + 1);

      if (resetSpinnerTimeout) {
        clearTimeout(resetSpinnerTimeout);
      }
      resetSpinnerTimeout = setTimeout(() => {
        setIsAutoRefreshing(false);
      }, 1200);
    };

    let interval: ReturnType<typeof setInterval> | null = null;
    const msUntilNextTick = Math.max(0, refreshRate - (Date.now() - lastRefreshTimeRef.current.getTime()));
    const timeout = setTimeout(() => {
      triggerAutoRefresh();
      interval = setInterval(() => {
        triggerAutoRefresh();
      }, refreshRate);
    }, msUntilNextTick);

    return () => {
      clearTimeout(timeout);
      if (resetSpinnerTimeout !== null) {
        clearTimeout(resetSpinnerTimeout);
      }
      if (interval !== null) {
        clearInterval(interval);
      }
      setIsAutoRefreshing(false);
    };
  }, [refreshRate]);

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
