import { useEffect } from 'react';

const useWidgetAutoRefresh = (reloadData: () => void, refreshInterval: number | null) => {
  useEffect(() => {
    const interval = refreshInterval !== null ? setInterval(() => {
      reloadData();
    }, refreshInterval) : null;
    return () => {
      if (interval !== null) {
        clearInterval(interval);
      }
    };
  }, [reloadData, refreshInterval]);
};
export default useWidgetAutoRefresh;
