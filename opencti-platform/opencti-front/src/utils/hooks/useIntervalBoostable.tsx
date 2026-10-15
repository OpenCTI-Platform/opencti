import { useEffect, useRef, useState } from 'react';
import useInterval from './useInterval';

const DEFAULT_BASE_FREQUENCY = 20000;
const DEFAULT_BOOST_FREQUENCY = 5000;
const DEFAULT_BOOST_DURATION = 30000;

type UseIntervalBoostableOptions = {
  baseFrequency?: number;
  boostFrequency?: number;
  boostDuration?: number;
};

/**
 * Custom useInterval hook where the interval can be boosted for a period of time.
 */
const useIntervalBoostable = (
  callback: () => void,
  options?: UseIntervalBoostableOptions,
) => {
  const {
    baseFrequency = DEFAULT_BASE_FREQUENCY,
    boostFrequency = DEFAULT_BOOST_FREQUENCY,
    boostDuration = DEFAULT_BOOST_DURATION,
  } = options ?? {
    baseFrequency: DEFAULT_BASE_FREQUENCY,
    boostFrequency: DEFAULT_BOOST_FREQUENCY,
    boostDuration: DEFAULT_BOOST_DURATION,
  };

  const refreshTimer = useRef<NodeJS.Timeout>(undefined);
  const [refreshFrequency, setRefreshFrequency] = useState(baseFrequency);

  useInterval(() => {
    callback();
  }, refreshFrequency);

  // Cancel a pending boost end so it does not update state after unmount
  useEffect(() => {
    return () => clearTimeout(refreshTimer.current);
  }, []);

  /**
   * Switches to the boost frequency, or extends a boost in progress, for the boost duration.
   */
  const activateBoost = () => {
    clearTimeout(refreshTimer.current);
    setRefreshFrequency(boostFrequency);
    refreshTimer.current = setTimeout(() => {
      setRefreshFrequency(baseFrequency);
    }, boostDuration);
  };

  return { activateBoost };
};

export default useIntervalBoostable;
