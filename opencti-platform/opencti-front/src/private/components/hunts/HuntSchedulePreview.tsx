import React, { useCallback, useMemo } from 'react';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { describeHuntSchedule, huntScheduleMode, type HuntScheduleValidation, nextHuntScheduleOccurrences, validateHuntSchedule } from './hunt-schedule-utils';
import useHuntMinScheduleInterval from './useHuntMinScheduleInterval';

const WEEK_DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

/** Translated, human readable sentence describing a hunt schedule. */
export const useHuntScheduleText = () => {
  const { t_i18n } = useFormatter();
  return useCallback((schedule?: string | null) => {
    const description = describeHuntSchedule(schedule);
    const values: Record<string, string | number> = { ...(description.values ?? {}) };
    if (description.weekDays) {
      values.days = description.weekDays.map((day) => t_i18n(WEEK_DAYS[day])).join(', ');
    }
    return t_i18n(description.message, { values });
  }, [t_i18n]);
};

/** Translated error of an invalid schedule, null when the schedule is valid. */
export const useHuntScheduleError = (minIntervalMinutes: number) => {
  const { t_i18n } = useFormatter();
  return useCallback((validation: HuntScheduleValidation) => {
    if (validation.valid) {
      return null;
    }
    switch (validation.code) {
      case 'never':
        return t_i18n('This cron expression never fires');
      case 'too_frequent':
        return t_i18n('A hunt cannot run more than once every {count} minutes', { values: { count: minIntervalMinutes } });
      default:
        return t_i18n('Invalid cron expression: {detail}', { values: { detail: validation.detail ?? '' } });
    }
  }, [t_i18n, minIntervalMinutes]);
};

interface HuntSchedulePreviewProps {
  schedule: string;
  occurrences?: number;
}

/** Description, validation and next occurrences of a schedule, displayed live under the schedule field. */
const HuntSchedulePreview = ({ schedule, occurrences = 3 }: HuntSchedulePreviewProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const scheduleText = useHuntScheduleText();
  const minIntervalMinutes = useHuntMinScheduleInterval();
  const scheduleError = useHuntScheduleError(minIntervalMinutes);
  const validation = useMemo(() => validateHuntSchedule(schedule, minIntervalMinutes), [schedule, minIntervalMinutes]);
  const nextRuns = useMemo(
    () => (validation.valid ? nextHuntScheduleOccurrences(schedule, occurrences) : []),
    [schedule, occurrences, validation.valid],
  );
  const error = scheduleError(validation);
  const isCron = huntScheduleMode(schedule) === 'cron';

  return (
    <div role="status" aria-live="polite" data-testid="hunt-schedule-preview" style={{ marginTop: theme.spacing(1) }}>
      {error ? (
        <Text variant="content-compact" style={{ color: theme.palette.error.main }}>{error}</Text>
      ) : (
        <>
          <Text variant="content-compact">{scheduleText(schedule)}</Text>
          {isCron && nextRuns.length > 0 && (
            <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>
              {t_i18n('Next runs')}: {nextRuns.map((date) => fldt(date)).join(' / ')}
            </Text>
          )}
        </>
      )}
    </div>
  );
};

export default HuntSchedulePreview;
