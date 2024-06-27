import { useCallback, useEffect, useRef } from 'react';

type CallbackFunction = (...args: never[]) => void;

const useDebounceCallback = (inputFunc: CallbackFunction, delay: number) => {
  const timeoutRef = useRef<number | null>(null);

  const debouncedFunction = useCallback((...args: never[]) => {
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
};

export default useDebounceCallback;
