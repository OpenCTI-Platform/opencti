import useHuntConfiguration from './useHuntConfiguration';

/** Minimum interval between two scheduled runs configured on the platform, the platform default until it is loaded. */
const useHuntMinScheduleInterval = (): number => useHuntConfiguration().minScheduleIntervalMinutes;

export default useHuntMinScheduleInterval;
