import { useEffect, useState } from 'react';
import { graphql } from 'react-relay';
import { fetchQuery } from '../../../relay/environment';
import { HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES } from './hunt-schedule-utils';
import { HUNT_MAX_IOCS_PER_RUN, HUNT_MAX_RELATED_SOURCES, HUNT_MAX_RESULTS_PER_RUN, HUNT_MAX_SIGMA_RULES, HUNT_MAX_TIME_WINDOW_HOURS } from './hunt-utils';
import { useHuntConfigurationQuery } from './__generated__/useHuntConfigurationQuery.graphql';

export const huntConfigurationQuery = graphql`
  query useHuntConfigurationQuery {
    huntConfiguration {
      min_schedule_interval_minutes
      default_expected_observables
      schedule_lookback_minutes
      max_time_window_hours
      max_results_per_run
      max_sigma_rules
      max_iocs_per_run
      max_related_sources
    }
  }
`;

// The overlap the platform applies by default between two recurring runs, until the configuration is loaded
export const HUNT_DEFAULT_SCHEDULE_LOOKBACK_MINUTES = 15;

export interface HuntConfiguration {
  /** Minimum interval between two scheduled runs, the platform default until it is loaded */
  minScheduleIntervalMinutes: number;
  /** Observable types a run extracts from its hits when its hunt names none, empty until loaded */
  defaultExpectedObservables: ReadonlyArray<string>;
  /** Overlap in minutes between a recurring run and the previous one, which catches the events indexed late */
  scheduleLookbackMinutes: number;
  /** Longest time window of a hunt or a run in hours, the platform default until it is loaded */
  maxTimeWindowHours: number;
  /** Most results a hunt asks of one run, the platform default until it is loaded */
  maxResultsPerRun: number;
  /** Most Sigma rules a hunt holds */
  maxSigmaRules: number;
  /** Most values an indicators hunt sends in one run */
  maxIocsPerRun: number;
  /** Most related threats a hunt from a threat reads its indicators from */
  maxRelatedSources: number;
}

const positiveOr = (value: number | null | undefined, fallback: number) => (typeof value === 'number' && value > 0 ? value : fallback);

/** The hunting configuration of the platform, read once and shared by every hunt form and page. */
const useHuntConfiguration = (): HuntConfiguration => {
  const [configuration, setConfiguration] = useState<HuntConfiguration>({
    minScheduleIntervalMinutes: HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES,
    defaultExpectedObservables: [],
    scheduleLookbackMinutes: HUNT_DEFAULT_SCHEDULE_LOOKBACK_MINUTES,
    maxTimeWindowHours: HUNT_MAX_TIME_WINDOW_HOURS,
    maxResultsPerRun: HUNT_MAX_RESULTS_PER_RUN,
    maxSigmaRules: HUNT_MAX_SIGMA_RULES,
    maxIocsPerRun: HUNT_MAX_IOCS_PER_RUN,
    maxRelatedSources: HUNT_MAX_RELATED_SOURCES,
  });
  useEffect(() => {
    const subscription = fetchQuery<useHuntConfigurationQuery>(huntConfigurationQuery, {}, { fetchPolicy: 'store-or-network' })
      .subscribe({
        next: (data) => {
          const minutes = data?.huntConfiguration?.min_schedule_interval_minutes;
          const lookback = data?.huntConfiguration?.schedule_lookback_minutes;
          setConfiguration({
            minScheduleIntervalMinutes: minutes && minutes > 0 ? minutes : HUNT_DEFAULT_MIN_SCHEDULE_INTERVAL_MINUTES,
            defaultExpectedObservables: data?.huntConfiguration?.default_expected_observables ?? [],
            scheduleLookbackMinutes: typeof lookback === 'number' && lookback >= 0 ? lookback : HUNT_DEFAULT_SCHEDULE_LOOKBACK_MINUTES,
            maxTimeWindowHours: positiveOr(data?.huntConfiguration?.max_time_window_hours, HUNT_MAX_TIME_WINDOW_HOURS),
            maxResultsPerRun: positiveOr(data?.huntConfiguration?.max_results_per_run, HUNT_MAX_RESULTS_PER_RUN),
            maxSigmaRules: positiveOr(data?.huntConfiguration?.max_sigma_rules, HUNT_MAX_SIGMA_RULES),
            maxIocsPerRun: positiveOr(data?.huntConfiguration?.max_iocs_per_run, HUNT_MAX_IOCS_PER_RUN),
            maxRelatedSources: positiveOr(data?.huntConfiguration?.max_related_sources, HUNT_MAX_RELATED_SOURCES),
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
