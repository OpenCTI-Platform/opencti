import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../relay/environment';
import { HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES } from './hunt-schedule-utils';
import { useHuntMinScheduleIntervalQuery } from './__generated__/useHuntMinScheduleIntervalQuery.graphql';

export const huntMinScheduleIntervalQuery = graphql`
  query useHuntMinScheduleIntervalQuery {
    huntConfiguration {
      min_schedule_interval_minutes
    }
  }
`;

/** Minimum interval between two scheduled runs configured on the platform, the platform default until it is loaded. */
const useHuntMinScheduleInterval = (): number => {
  const [minutes, setMinutes] = useState(HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES);
  useEffect(() => {
    const subscription = fetchQuery<useHuntMinScheduleIntervalQuery>(huntMinScheduleIntervalQuery, {}, { fetchPolicy: 'store-or-network' })
      .subscribe({
        next: (data) => {
          const value = data?.huntConfiguration?.min_schedule_interval_minutes;
          if (value && value > 0) {
            setMinutes(value);
          }
        },
        // On failure the default stays: the platform validates the schedule again on save
        error: () => {},
      });
    return () => subscription.unsubscribe();
  }, []);
  return minutes;
};

export default useHuntMinScheduleInterval;
