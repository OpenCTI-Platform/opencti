import { useState, useEffect } from 'react';

interface UseNetworkCheckResult {
  isReachable: boolean | null;
  isLoading: boolean;
}

const useNetworkCheck = (url?: string | null): UseNetworkCheckResult => {
  if (!url) {
    return {
      isReachable: false,
      isLoading: false,
    };
  }
  const [isReachable, setIsReachable] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  useEffect(() => {
    const checkNetwork = async () => {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        await fetch(url, {
          method: 'HEAD',
          mode: 'no-cors',
          signal: controller.signal,
        });

        clearTimeout(timeoutId);
        setIsReachable(true);
      } catch {
        setIsReachable(false);
      } finally {
        setIsLoading(false);
      }
    };

    checkNetwork();
  }, []); // Empty dependency array - only runs on mount

  return { isReachable, isLoading };
};

export default useNetworkCheck;
