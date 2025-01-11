import { useCallback, useEffect, useRef } from 'react';

type CallbackFunction<Args> = (...args: Args[]) => void;

function useDebounceCallback<A>(inputFunc: CallbackFunction<A>, delay: number) {
  const timeoutRef = useRef<number | null>(null);

  const debouncedFunction = useCallback((...args: A[]) => {
    if (timeoutRef.current !== null) {
      clearTimeout(timeoutRef.current);
    }

    timeoutRef.current = window.setTimeout(() => {
      inputFunc(...args);
    }, delay);
  }, [inputFunc, delay]);

  // Clear timeout if the component unmounts or delay changes
  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) {
        clearTimeout(timeoutRef.current);
      }
    };
  }, [delay]);

  return debouncedFunction;
}

export default useDebounceCallback;
