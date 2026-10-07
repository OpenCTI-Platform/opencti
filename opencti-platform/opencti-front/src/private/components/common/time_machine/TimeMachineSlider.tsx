import React, { useEffect, useMemo, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Slider, Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { Box } from '@mui/material';
import { useTheme } from '@mui/styles';
import { NavigateBeforeOutlined, NavigateNextOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import DateTimePicker from '../../../../components/common/input/DateTimePicker';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { clampDate } from './timeMachineUtils';
import { TimeMachineSliderTimelineQuery } from './__generated__/TimeMachineSliderTimelineQuery.graphql';

export const timeMachineSliderTimelineQuery = graphql`
  query TimeMachineSliderTimelineQuery($id: String!) {
    entityTimeMachineTimeline(id: $id) {
      entity_id
      created_at
      history_start
      events {
        date
        event_scope
      }
      events_truncated
      snapshots
      max_replay_days
    }
  }
`;

const HOUR_MS = 60 * 60 * 1000;

interface TimeMachineSliderProps {
  entityId: string;
  value: string;
  onChange: (date: string) => void;
}

const TimeMachineSlider = ({ entityId, value, onChange }: TimeMachineSliderProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, fsd } = useFormatter();
  const data = useLazyLoadQuery<TimeMachineSliderTimelineQuery>(timeMachineSliderTimelineQuery, { id: entityId }, { fetchPolicy: 'store-and-network' });
  const timeline = data.entityTimeMachineTimeline;
  const max = Date.now();
  const valueTime = new Date(value).getTime();
  const candidates = [timeline?.created_at, timeline?.history_start]
    .filter((date): date is string => !!date)
    .map((date) => new Date(date).getTime());
  const knownStart = candidates.length > 0 ? Math.min(...candidates) : max - 365 * 24 * HOUR_MS;
  // The selected date may precede the creation of the entity ("did not exist" state)
  const min = Number.isNaN(valueTime) ? knownStart : Math.min(knownStart, valueTime);
  const [position, setPosition] = useState(new Date(value).getTime());
  useEffect(() => setPosition(new Date(value).getTime()), [value]);

  const eventTimes = useMemo(() => {
    const times = (timeline?.events ?? []).map((event) => new Date(event.date).getTime());
    return [...new Set(times)].sort((a, b) => a - b);
  }, [timeline]);
  const snapshotTimes = useMemo(() => (timeline?.snapshots ?? []).map((date) => new Date(date).getTime()), [timeline]);
  const current = clampDate(position, min, max);
  const previousChange = [...eventTimes].reverse().find((time) => time < current);
  const nextChange = eventTimes.find((time) => time > current);
  const span = Math.max(max - min, 1);
  const historyStartsAfterCreation = timeline?.history_start && timeline?.created_at
    && new Date(timeline.history_start).getTime() > new Date(timeline.created_at).getTime();

  const commit = (time: number) => onChange(new Date(clampDate(time, min, max)).toISOString());

  return (
    <Box data-testid="time-machine-slider">
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', marginBottom: 1 }}>
        <DateTimePicker
          label={t_i18n('View as of')}
          value={new Date(current)}
          minDateTime={new Date(min)}
          maxDateTime={new Date(max)}
          onAccept={(date) => {
            if (date && !Number.isNaN(date.getTime())) commit(date.getTime());
          }}
          slotProps={{ textField: { inputProps: { 'aria-label': t_i18n('View as of') } } }}
        />
        <Button
          variant="secondary"
          startIcon={<NavigateBeforeOutlined fontSize="small" />}
          disabled={previousChange === undefined}
          onClick={() => previousChange !== undefined && commit(previousChange)}
        >
          {t_i18n('Previous change')}
        </Button>
        <Button
          variant="secondary"
          endIcon={<NavigateNextOutlined fontSize="small" />}
          disabled={nextChange === undefined}
          onClick={() => nextChange !== undefined && commit(nextChange)}
        >
          {t_i18n('Next change')}
        </Button>
      </Box>
      <Slider
        aria-label={t_i18n('Time machine date')}
        min={min}
        max={max}
        step={HOUR_MS}
        value={[current]}
        onValueChange={([time]) => setPosition(time)}
        onValueCommit={([time]) => commit(time)}
        showBounds
        minLabel={fsd(new Date(min))}
        maxLabel={t_i18n('Now')}
      />
      <Box sx={{ position: 'relative', height: 14, marginTop: 0.5 }} aria-hidden={eventTimes.length === 0}>
        {eventTimes.map((time) => (
          <Tooltip key={`event-${time}`}>
            <TooltipTrigger asChild>
              <Box
                component="button"
                type="button"
                aria-label={t_i18n('Change on {date}', { values: { date: fldt(new Date(time)) } })}
                onClick={() => commit(time)}
                sx={{
                  position: 'absolute',
                  left: `${((time - min) / span) * 100}%`,
                  width: 3,
                  height: 12,
                  padding: 0,
                  border: 'none',
                  cursor: 'pointer',
                  transform: 'translateX(-50%)',
                  backgroundColor: theme.palette.primary.main,
                  opacity: time <= current ? 1 : 0.4,
                }}
              />
            </TooltipTrigger>
            <TooltipContent>{t_i18n('Change on {date}', { values: { date: fldt(new Date(time)) } })}</TooltipContent>
          </Tooltip>
        ))}
        {snapshotTimes.map((time) => (
          <Box
            key={`snapshot-${time}`}
            sx={{
              position: 'absolute',
              left: `${((time - min) / span) * 100}%`,
              top: 12,
              width: 6,
              height: 2,
              transform: 'translateX(-50%)',
              backgroundColor: theme.palette.text.secondary,
            }}
          />
        ))}
      </Box>
      {historyStartsAfterCreation && (
        <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)', marginTop: 8 }}>
          {t_i18n('History is retained since {date}.', { values: { date: fldt(timeline.history_start) } })}
        </Text>
      )}
      {timeline?.events_truncated && (
        <Text variant="content-caption" as="p" style={{ color: 'var(--text-default-secondary)', marginTop: 8 }} data-testid="time-machine-slider-truncated">
          {t_i18n('Only the most recent changes are marked on the slider, older dates can still be selected.')}
        </Text>
      )}
    </Box>
  );
};

export default TimeMachineSlider;
