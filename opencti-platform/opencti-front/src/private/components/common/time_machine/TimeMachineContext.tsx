import React, { createContext, ReactNode, useCallback, useContext, useMemo } from 'react';
import { useSearchParams } from 'react-router';
import { isValidDate } from './timeMachineUtils';

export const AS_OF_SEARCH_PARAM = 'asOf';

interface TimeMachineContextValue {
  // Date of the read-only as-of view, null when the current knowledge is displayed
  asOfDate: string | null;
  setAsOfDate: (date: string | null) => void;
}

const TimeMachineContext = createContext<TimeMachineContextValue>({
  asOfDate: null,
  setAsOfDate: () => undefined,
});

/**
 * Holds the state of the "View as of" mode of an entity.
 * The date is kept in the URL so an as-of view can be shared and survives a reload.
 */
export const TimeMachineProvider = ({ children }: { children: ReactNode }) => {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawDate = searchParams.get(AS_OF_SEARCH_PARAM);
  const asOfDate = isValidDate(rawDate) ? rawDate : null;
  const setAsOfDate = useCallback((date: string | null) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (date) {
        next.set(AS_OF_SEARCH_PARAM, date);
      } else {
        next.delete(AS_OF_SEARCH_PARAM);
      }
      return next;
    }, { replace: true });
  }, [setSearchParams]);
  const value = useMemo(() => ({ asOfDate, setAsOfDate }), [asOfDate, setAsOfDate]);
  return <TimeMachineContext.Provider value={value}>{children}</TimeMachineContext.Provider>;
};

export const useTimeMachine = () => useContext(TimeMachineContext);
