import { useCallback, useEffect, useRef } from 'react';

type CallbackFunction<Args extends unknown[]> = (...args: Args) => void;
type DebouncedCallback<Args extends unknown[]> = ((...args: Args) => void) & { cancel: () => void };

function useDebounceCallback<A extends unknown[]>(inputFunc: CallbackFunction<A>, delay: number): DebouncedCallback<A> {
  const timeoutRef = useRef<number | null>(null);

  const cancel = useCallback(() => {
    if (timeoutRef.current !== null) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);

  const debouncedFunction = useCallback((...args: A) => {
    cancel();

    timeoutRef.current = window.setTimeout(() => {
      inputFunc(...args);
      timeoutRef.current = null;
    }, delay);
  }, [cancel, inputFunc, delay]);

  const debouncedWithCancel = debouncedFunction as DebouncedCallback<A>;
  debouncedWithCancel.cancel = cancel;

  // Clear timeout if the component unmounts or delay changes
  useEffect(() => {
    return () => {
      cancel();
    };
  }, [delay, cancel]);

  return debouncedWithCancel;
}

export default useDebounceCallback;
