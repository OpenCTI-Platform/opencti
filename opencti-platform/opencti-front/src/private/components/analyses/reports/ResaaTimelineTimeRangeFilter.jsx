import React, { useMemo } from 'react';
import Box from '@mui/material/Box';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import {
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  XAxis,
  YAxis,
  ZAxis,
} from 'recharts';
import {
  addDays,
  addHours,
  addMilliseconds,
  addMonths,
  addYears,
  differenceInMilliseconds,
  subMonths,
  subYears,
  endOfDay,
  endOfHour,
  endOfMonth,
  endOfYear,
  isBefore,
  isEqual,
  startOfDay,
  startOfHour,
  startOfMonth,
  startOfYear,
} from 'date-fns';
import TimeRange from '../../../../components/range_slider/RangeSlider';
import { useFormatter } from '../../../../components/i18n';

export const TIME_GRANULARITIES = ['hourly', 'daily', 'monthly', 'yearly'];

const MAX_LABEL_COUNT = 12;

const GRANULARITY_STEP_MS = {
  hourly: 60 * 60 * 1000,
  daily: 24 * 60 * 60 * 1000,
  monthly: 30 * 24 * 60 * 60 * 1000,
  yearly: 365 * 24 * 60 * 60 * 1000,
};

const advanceByGranularity = (date, granularity) => {
  switch (granularity) {
    case 'hourly':
      return addHours(date, 1);
    case 'daily':
      return addDays(date, 1);
    case 'monthly':
      return addMonths(date, 1);
    case 'yearly':
      return addYears(date, 1);
    default:
      return addDays(date, 1);
  }
};

export const alignTimelineIntervalToGranularity = (interval, granularity) => ([
  snapDateToGranularity(interval[0], granularity, 'start'),
  snapDateToGranularity(interval[1], granularity, 'end'),
]);

export const generateCalendarTickValues = (interval, granularity) => {
  const ticks = [];
  const alignedInterval = alignTimelineIntervalToGranularity(interval, granularity);
  let current = alignedInterval[0];
  const end = alignedInterval[1];

  while (isBefore(current, end) || isEqual(current, end)) {
    ticks.push(current.getTime());
    current = advanceByGranularity(current, granularity);
    if (ticks.length > 2000) {
      break;
    }
  }

  return ticks;
};

const snapToNearestTickValue = (date, tickValues) => {
  if (!tickValues?.length) {
    return date;
  }
  const target = date.getTime();
  const nearest = tickValues.reduce(
    (best, tick) => (Math.abs(tick - target) < Math.abs(best - target) ? tick : best),
    tickValues[0],
  );
  return new Date(nearest);
};

export const snapIntervalToTickValues = (interval, tickValues, bounds) => {
  const [min, max] = bounds;
  let start = snapToNearestTickValue(interval[0], tickValues);
  let end = snapToNearestTickValue(interval[1], tickValues);
  if (end.getTime() < start.getTime()) {
    const swap = start;
    start = end;
    end = swap;
  }
  return [
    clampDate(start, min, max),
    clampDate(end, min, max),
  ];
};

export const isWithinTimelineInterval = (time, interval) => {
  const timestamp = time instanceof Date ? time.getTime() : time;
  if (Number.isNaN(timestamp)) {
    return false;
  }
  return timestamp >= interval[0].getTime() && timestamp <= interval[1].getTime();
};

export const computeResaaTimelineInterval = (dates) => {
  const validDates = dates.filter((date) => date && !Number.isNaN(date.getTime()));
  if (validDates.length === 0) {
    const now = new Date();
    return [addMilliseconds(now, -24 * 60 * 60 * 1000), now];
  }
  const minTime = Math.min(...validDates.map((date) => date.getTime()));
  const maxTime = Math.max(...validDates.map((date) => date.getTime()));
  if (minTime === maxTime) {
    const single = new Date(minTime);
    return [addMilliseconds(single, -12 * 60 * 60 * 1000), addMilliseconds(single, 12 * 60 * 60 * 1000)];
  }
  const span = maxTime - minTime;
  const padding = Math.max(span * 0.05, 30 * 60 * 1000);
  return [new Date(minTime - padding), new Date(maxTime + padding)];
};

const getDataTimeExtent = (dates) => {
  const validDates = dates.filter((date) => date && !Number.isNaN(date.getTime()));
  if (validDates.length === 0) {
    const now = new Date();
    return { min: now, max: now, center: now };
  }
  const min = new Date(Math.min(...validDates.map((date) => date.getTime())));
  const max = new Date(Math.max(...validDates.map((date) => date.getTime())));
  const center = new Date((min.getTime() + max.getTime()) / 2);
  return { min, max, center };
};

const HOURLY_VIEWPORT_MS = 3 * 24 * 60 * 60 * 1000;

const getViewportAroundCenter = (center, granularity) => {
  switch (granularity) {
    case 'hourly': {
      const halfSpan = HOURLY_VIEWPORT_MS / 2;
      return {
        start: startOfHour(new Date(center.getTime() - halfSpan)),
        end: endOfHour(new Date(center.getTime() + halfSpan)),
      };
    }
    case 'daily':
      return {
        start: startOfDay(subMonths(center, 1)),
        end: endOfDay(addMonths(center, 1)),
      };
    case 'monthly':
      return {
        start: startOfMonth(subYears(center, 2)),
        end: endOfMonth(addYears(center, 3)),
      };
    case 'yearly':
      return {
        start: startOfYear(subYears(center, 20)),
        end: endOfYear(addYears(center, 20)),
      };
    default:
      return {
        start: startOfDay(subMonths(center, 1)),
        end: endOfDay(addMonths(center, 1)),
      };
  }
};

export const computeTimelineAxisInterval = (granularity, dates) => {
  const { center } = getDataTimeExtent(dates);
  const { start, end } = getViewportAroundCenter(center, granularity);
  return alignTimelineIntervalToGranularity([start, end], granularity);
};

export const inferDefaultTimeGranularity = (interval) => {
  const spanMs = differenceInMilliseconds(interval[1], interval[0]);
  const days = spanMs / (24 * 60 * 60 * 1000);
  if (days <= 3) {
    return 'hourly';
  }
  if (days <= 90) {
    return 'daily';
  }
  if (days <= 730) {
    return 'monthly';
  }
  return 'yearly';
};

const clampDate = (date, min, max) => {
  const time = date.getTime();
  if (time < min.getTime()) {
    return min;
  }
  if (time > max.getTime()) {
    return max;
  }
  return date;
};

export const snapDateToGranularity = (date, granularity, bound = 'start') => {
  const normalized = new Date(date);
  if (bound === 'end') {
    switch (granularity) {
      case 'hourly':
        return endOfHour(normalized);
      case 'daily':
        return endOfDay(normalized);
      case 'monthly':
        return endOfMonth(normalized);
      case 'yearly':
        return endOfYear(normalized);
      default:
        return normalized;
    }
  }
  switch (granularity) {
    case 'hourly':
      return startOfHour(normalized);
    case 'daily':
      return startOfDay(normalized);
    case 'monthly':
      return startOfMonth(normalized);
    case 'yearly':
      return startOfYear(normalized);
    default:
      return normalized;
  }
};

export const snapIntervalToGranularity = (interval, granularity, bounds) => {
  const [min, max] = bounds;
  const start = clampDate(
    snapDateToGranularity(interval[0], granularity, 'start'),
    min,
    max,
  );
  let end = clampDate(
    snapDateToGranularity(interval[1], granularity, 'end'),
    min,
    max,
  );
  if (end.getTime() < start.getTime()) {
    end = snapDateToGranularity(start, granularity, 'end');
  }
  return [start, end];
};

const ResaaHourlyTickLabel = ({ timestamp, formatDate, formatTime }) => (
  <>
    <span className="resaa-timeline-tick-label__date">{formatDate(timestamp)}</span>
    <span className="resaa-timeline-tick-label__time">{formatTime(timestamp)}</span>
  </>
);

const formatHourlyTick = (ms, formatDate, formatTime) => (
  <ResaaHourlyTickLabel
    timestamp={new Date(ms)}
    formatDate={formatDate}
    formatTime={formatTime}
  />
);

const MARKER_VERTICAL_OFFSET = 14;

const TimelineMarkerShape = ({
  cx,
  cy,
  payload,
}) => {
  if (cx == null || cy == null || !payload) {
    return null;
  }
  return (
    <rect
      x={cx - 1.5}
      y={cy - 11 - MARKER_VERTICAL_OFFSET}
      width={3}
      height={22}
      fill={payload.color}
      opacity={0.92}
      rx={0.5}
    />
  );
};

const ResaaTimelineTimeRangeFilter = ({
  items,
  timelineInterval,
  selectedInterval,
  granularity,
  onGranularityChange,
  onChange,
}) => {
  const { fsd, md, yd, nt, t_i18n } = useFormatter();
  const isHourlyGranularity = granularity === 'hourly';

  const alignedTimelineInterval = useMemo(
    () => alignTimelineIntervalToGranularity(timelineInterval, granularity),
    [timelineInterval, granularity],
  );

  const tickValues = useMemo(
    () => generateCalendarTickValues(alignedTimelineInterval, granularity),
    [alignedTimelineInterval, granularity],
  );

  const tickLabelEvery = useMemo(() => {
    if (tickValues.length <= MAX_LABEL_COUNT) {
      return 1;
    }
    return Math.ceil(tickValues.length / MAX_LABEL_COUNT);
  }, [tickValues]);

  const step = useMemo(() => {
    if (tickValues.length >= 2) {
      return tickValues[1] - tickValues[0];
    }
    return GRANULARITY_STEP_MS[granularity];
  }, [tickValues, granularity]);

  const formatTick = useMemo(() => {
    switch (granularity) {
      case 'hourly':
        return (ms) => formatHourlyTick(ms, fsd, nt);
      case 'daily':
        return (ms) => fsd(new Date(ms));
      case 'monthly':
        return (ms) => md(new Date(ms));
      case 'yearly':
        return (ms) => yd(new Date(ms));
      default:
        return (ms) => fsd(new Date(ms));
    }
  }, [granularity, fsd, md, yd, nt]);

  const timeDomain = useMemo(
    () => [alignedTimelineInterval[0].getTime(), alignedTimelineInterval[1].getTime()],
    [alignedTimelineInterval],
  );

  const axisItems = useMemo(
    () => items.filter((item) => isWithinTimelineInterval(item.time, alignedTimelineInterval)),
    [items, alignedTimelineInterval],
  );

  const scatterData = useMemo(
    () => axisItems.map((item) => ({
      id: item.id,
      time: item.time.getTime(),
      index: 1,
      value: 1,
      color: item.color,
    })),
    [axisItems],
  );

  const snappedSelectedInterval = useMemo(
    () => snapIntervalToTickValues(selectedInterval, tickValues, alignedTimelineInterval),
    [selectedInterval, tickValues, alignedTimelineInterval],
  );

  const handleTimeRangeChange = (interval) => {
    if (!interval || interval.length !== 2) {
      return;
    }
    onChange(snapIntervalToTickValues(interval, tickValues, alignedTimelineInterval));
  };

  const handleGranularityChange = (_event, value) => {
    if (!value || !TIME_GRANULARITIES.includes(value)) {
      return;
    }
    onGranularityChange(value);
  };

  if (items.length === 0) {
    return null;
  }

  return (
    <Box sx={{ marginBottom: 3, width: '100%' }}>
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'flex-end',
          marginBottom: 1.5,
        }}
      >
        <ToggleButtonGroup
          size="small"
          exclusive
          value={granularity}
          onChange={handleGranularityChange}
          aria-label={t_i18n('Time step')}
        >
          <ToggleButton value="hourly">
            {t_i18n('Hourly')}
          </ToggleButton>
          <ToggleButton value="daily">
            {t_i18n('Daily')}
          </ToggleButton>
          <ToggleButton value="monthly">
            {t_i18n('Monthly')}
          </ToggleButton>
          <ToggleButton value="yearly">
            {t_i18n('Yearly')}
          </ToggleButton>
        </ToggleButtonGroup>
      </Box>
      <Box
        sx={{
          position: 'relative',
          height: isHourlyGranularity ? 100 : 88,
          width: '100%',
          overflow: 'visible',
        }}
      >
        <Box
          sx={{
            width: '90%',
            marginX: 'auto',
            height: 60,
            pointerEvents: 'none',
          }}
        >
          <ResponsiveContainer width="100%" height={60}>
            <ScatterChart
              height={60}
              margin={{ top: 20, bottom: 0, left: 0, right: 0 }}
            >
              <XAxis
                type="number"
                dataKey="time"
                domain={timeDomain}
                hide
              />
              <YAxis
                type="number"
                dataKey="index"
                name="scatter"
                width={0}
                tick={false}
                tickLine={false}
                axisLine={false}
                domain={[0.5, 1.5]}
              />
              <ZAxis
                type="number"
                dataKey="value"
                range={[100, 100]}
              />
              <Scatter
                data={scatterData}
                shape={TimelineMarkerShape}
              />
            </ScatterChart>
          </ResponsiveContainer>
        </Box>
        <Box
          sx={{
            position: 'absolute',
            top: 30,
            left: 0,
            right: 0,
            bottom: 0,
          }}
        >
          <TimeRange
            key={granularity}
            ticksNumber={tickValues.length || 1}
            tickValues={tickValues}
            showUnitTickMarkers
            tickLabelEvery={tickLabelEvery}
            selectedInterval={snappedSelectedInterval}
            timelineInterval={alignedTimelineInterval}
            step={step}
            onUpdateCallback={() => null}
            onChangeCallback={handleTimeRangeChange}
            formatTick={formatTick}
            tickLabelMultiline={isHourlyGranularity}
            containerClassName={`timerange resaa-timeline-timerange${isHourlyGranularity ? ' resaa-timeline-timerange--hourly' : ''}`}
          />
        </Box>
      </Box>
    </Box>
  );
};

export default ResaaTimelineTimeRangeFilter;
