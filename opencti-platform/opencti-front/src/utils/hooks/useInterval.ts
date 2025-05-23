import { useEffect, useRef } from 'react';

// Custom useInterval hook.
const useInterval = (callback: () => void, delay: number, immediate = true) => {
  const savedCallback = useRef<() => void>(undefined);

  // Remember the latest callback.
  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  // Combining the setInterval and
  // clearInterval methods based on delay.
  useEffect(() => {
    function func() {
      savedCallback.current?.();
    }
    if (immediate) func();
    const id = setInterval(func, delay);
    return () => clearInterval(id);
  }, [delay]);
};

export default useInterval;
