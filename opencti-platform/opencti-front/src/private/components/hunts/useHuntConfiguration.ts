import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../relay/environment';
import { HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES } from './hunt-schedule-utils';
import { useHuntConfigurationQuery } from './__generated__/useHuntConfigurationQuery.graphql';

export const huntConfigurationQuery = graphql`
  query useHuntConfigurationQuery {
    huntConfiguration {
      min_schedule_interval_minutes
      default_expected_observables
    }
  }
`;

export interface HuntConfiguration {
  /** Minimum interval between two scheduled runs, the platform default until it is loaded */
  minScheduleIntervalMinutes: number;
  /** Observable types a run extracts from its hits when its hunt names none, empty until loaded */
  defaultExpectedObservables: ReadonlyArray<string>;
}

/** The hunting configuration of the platform, read once and shared by every hunt form and page. */
const useHuntConfiguration = (): HuntConfiguration => {
  const [configuration, setConfiguration] = useState<HuntConfiguration>({
    minScheduleIntervalMinutes: HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES,
    defaultExpectedObservables: [],
  });
  useEffect(() => {
    const subscription = fetchQuery<useHuntConfigurationQuery>(huntConfigurationQuery, {}, { fetchPolicy: 'store-or-network' })
      .subscribe({
        next: (data) => {
          const minutes = data?.huntConfiguration?.min_schedule_interval_minutes;
          setConfiguration({
            minScheduleIntervalMinutes: minutes && minutes > 0 ? minutes : HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES,
            defaultExpectedObservables: data?.huntConfiguration?.default_expected_observables ?? [],
          });
        },
        // On failure the defaults stay: the platform validates the schedule again on save
        error: () => {},
      });
    return () => subscription.unsubscribe();
  }, []);
  return configuration;
};

export default useHuntConfiguration;
