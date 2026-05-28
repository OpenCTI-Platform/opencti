import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import { ChevronLeft, ChevronRight } from '@mui/icons-material';
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
  const startTime = alignedInterval[0].getTime();
  const endTime = end.getTime();

  while (isBefore(current, end) || isEqual(current, end)) {
    ticks.push(current.getTime());
    current = advanceByGranularity(current, granularity);
    if (ticks.length > 2000) {
      break;
    }
  }

  if (ticks.length === 0) {
    return [startTime, endTime];
  }
  if (ticks[0] !== startTime) {
    ticks.unshift(startTime);
  }
  const useMonthYearStartTicksOnly = granularity === 'monthly' || granularity === 'yearly';
  if (!useMonthYearStartTicksOnly && ticks[ticks.length - 1] !== endTime) {
    ticks.push(endTime);
  }

  return ticks;
};

export const getTimelineSliderStep = (tickValues, granularity) => {
  if (tickValues.length < 2) {
    return GRANULARITY_STEP_MS[granularity] ?? 1;
  }
  if (granularity === 'monthly' || granularity === 'yearly') {
    const span = tickValues[tickValues.length - 1] - tickValues[0];
    return Math.max(1, Math.round(span / (tickValues.length - 1)));
  }
  return tickValues[1] - tickValues[0];
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

const SNAP_EDGE_TOLERANCE_MS = 60 * 1000;

const getSnapEdgeThresholdMs = (tickValues) => {
  if (tickValues.length >= 2) {
    return Math.max(
      (tickValues[tickValues.length - 1] - tickValues[tickValues.length - 2]) / 2,
      SNAP_EDGE_TOLERANCE_MS,
    );
  }
  return SNAP_EDGE_TOLERANCE_MS;
};

export const snapIntervalToTickValues = (interval, tickValues, bounds) => {
  const [min, max] = bounds;
  const minTime = min.getTime();
  const maxTime = max.getTime();
  const edgeThreshold = getSnapEdgeThresholdMs(tickValues);

  let start = interval[0].getTime() <= minTime + edgeThreshold
    ? min
    : snapToNearestTickValue(interval[0], tickValues);
  let end = interval[1].getTime() >= maxTime - edgeThreshold
    ? max
    : snapToNearestTickValue(interval[1], tickValues);

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

export const centerTimelineViewportOn = (center, granularity) => {
  const { start, end } = getViewportAroundCenter(center, granularity);
  return alignTimelineIntervalToGranularity([start, end], granularity);
};

export const shiftTimelineViewport = (viewport, granularity, direction) => {
  const spanMs = viewport[1].getTime() - viewport[0].getTime();
  const centerMs = (viewport[0].getTime() + viewport[1].getTime()) / 2;
  const newCenter = new Date(centerMs + (direction * spanMs));
  return centerTimelineViewportOn(newCenter, granularity);
};

const VIEWPORT_PAN_EDGE_TOLERANCE_MS = 60 * 1000;

export const getTimelineViewportPanState = (viewport, dataExtent) => {
  const viewportStart = viewport[0].getTime();
  const viewportEnd = viewport[1].getTime();
  const extentStart = dataExtent[0].getTime();
  const extentEnd = dataExtent[1].getTime();

  const coversFullDataExtent = viewportStart <= extentStart + VIEWPORT_PAN_EDGE_TOLERANCE_MS
    && viewportEnd >= extentEnd - VIEWPORT_PAN_EDGE_TOLERANCE_MS;

  return {
    canPanBackward: !coversFullDataExtent
      && viewportStart > extentStart + VIEWPORT_PAN_EDGE_TOLERANCE_MS,
    canPanForward: !coversFullDataExtent
      && viewportEnd < extentEnd - VIEWPORT_PAN_EDGE_TOLERANCE_MS,
  };
};

export const computeTimelineAxisInterval = (granularity, dates) => {
  const { center } = getDataTimeExtent(dates);
  return centerTimelineViewportOn(center, granularity);
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

const ResaaTimelineTickLabel = ({ timestamp, formatPrimary, formatTime, showTime }) => (
  <>
    <span className="resaa-timeline-tick-label__date">{formatPrimary(timestamp)}</span>
    <span
      className={`resaa-timeline-tick-label__time${showTime ? '' : ' resaa-timeline-tick-label__time--placeholder'}`}
      aria-hidden={!showTime}
    >
      {showTime ? formatTime(timestamp) : '\u00A0'}
    </span>
  </>
);

const TIMELINE_MARKER_HEIGHT = 36;
const MARKER_VERTICAL_OFFSET = 7;
const SCATTER_MARGIN_TOP = 0;
const TIMELINE_RAIL_TOP_OFFSET = 22;
const TIMELINE_RAIL_BAND_HEIGHT = 50;
const TIMELINE_SECTION_HEIGHT = 96;

const toIntervalPercent = (time, extentStart, extentSpan) => (
  ((time - extentStart) / extentSpan) * 100
);

const TIMELINE_TOOLBAR_CONTROL_HEIGHT = 36;

const minimapPanButtonSx = {
  flexShrink: 0,
  width: TIMELINE_TOOLBAR_CONTROL_HEIGHT,
  height: TIMELINE_TOOLBAR_CONTROL_HEIGHT,
  borderRadius: 0,
  color: '#5f6b7a',
  '&:hover': {
    backgroundColor: 'rgba(74, 134, 232, 0.14)',
    color: '#4a86e8',
  },
  '&.Mui-disabled': {
    color: '#b0b8c4',
    backgroundColor: 'transparent',
  },
};

const ResaaTimelineMinimap = ({
  dataExtent,
  viewportInterval,
  items,
  onNavigate,
}) => {
  const extentStart = dataExtent[0].getTime();
  const extentEnd = dataExtent[1].getTime();
  const extentSpan = Math.max(extentEnd - extentStart, 1);

  const visibleViewport = useMemo(() => {
    const rawLeft = toIntervalPercent(viewportInterval[0].getTime(), extentStart, extentSpan);
    const rawRight = toIntervalPercent(viewportInterval[1].getTime(), extentStart, extentSpan);
    const visibleLeft = Math.max(0, rawLeft);
    const visibleRight = Math.min(100, rawRight);
    const visibleWidth = visibleRight - visibleLeft;
    if (visibleWidth <= 0) {
      return null;
    }
    return { left: visibleLeft, width: visibleWidth };
  }, [viewportInterval, extentStart, extentSpan]);

  const handleTrackClick = useCallback((event) => {
    const rect = event.currentTarget.getBoundingClientRect();
    const ratio = Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width));
    const centerTime = extentStart + (ratio * extentSpan);
    onNavigate(new Date(centerTime));
  }, [extentSpan, extentStart, onNavigate]);

  return (
    <Box
      role="button"
      tabIndex={0}
      onClick={handleTrackClick}
      className="resaa-timeline-minimap"
      sx={{
        position: 'relative',
        flex: 1,
        height: TIMELINE_TOOLBAR_CONTROL_HEIGHT,
        cursor: 'pointer',
        overflow: 'hidden',
      }}
    >
      {items.map((item) => {
        const left = toIntervalPercent(item.time.getTime(), extentStart, extentSpan);
        return (
          <Box
            key={item.id}
            className="resaa-timeline-minimap__marker"
            sx={{
              position: 'absolute',
              left: `${left}%`,
              top: '50%',
              width: 5,
              height: 14,
              transform: 'translate(-50%, -50%)',
              borderRadius: 2.5,
              backgroundColor: item.color,
              opacity: 0.9,
              pointerEvents: 'none',
            }}
          />
        );
      })}
      {visibleViewport && (
        <Box
          className="resaa-timeline-minimap__viewport"
          sx={{
            position: 'absolute',
            left: `${visibleViewport.left}%`,
            width: `${visibleViewport.width}%`,
            top: 2,
            bottom: 2,
            borderRadius: 0.5,
            border: '2px solid #4a86e8',
            backgroundColor: 'rgba(74, 134, 232, 0.18)',
            pointerEvents: 'none',
            boxSizing: 'border-box',
          }}
        />
      )}
    </Box>
  );
};

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
      x={cx - 2.5}
      y={cy - (TIMELINE_MARKER_HEIGHT / 2) - MARKER_VERTICAL_OFFSET}
      width={5}
      height={TIMELINE_MARKER_HEIGHT}
      fill={payload.color}
      opacity={0.92}
      rx={2.5}
      ry={2.5}
    />
  );
};

const ResaaTimelineTimeRangeFilter = ({
  items,
  dataExtent,
  timelineInterval,
  selectedInterval,
  granularity,
  onGranularityChange,
  onViewportPan,
  onViewportNavigate,
  onChange,
}) => {
  const { fsd, md, yd, nt, t_i18n } = useFormatter();
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

  const step = useMemo(
    () => getTimelineSliderStep(tickValues, granularity),
    [tickValues, granularity],
  );

  const [dragSelection, setDragSelection] = useState(null);

  const formatTick = useMemo(() => {
    const formatPrimary = (() => {
      switch (granularity) {
        case 'hourly':
        case 'daily':
          return fsd;
        case 'monthly':
          return md;
        case 'yearly':
          return yd;
        default:
          return fsd;
      }
    })();

    return function formatResaaTimelineTick(ms) {
      return (
        <ResaaTimelineTickLabel
          timestamp={new Date(ms)}
          formatPrimary={formatPrimary}
          formatTime={nt}
          showTime={granularity === 'hourly'}
        />
      );
    };
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

  const displaySelectedInterval = dragSelection ?? snappedSelectedInterval;

  useEffect(() => {
    setDragSelection(null);
  }, [granularity, alignedTimelineInterval[0].getTime(), alignedTimelineInterval[1].getTime()]);

  const { canPanBackward, canPanForward } = useMemo(
    () => getTimelineViewportPanState(alignedTimelineInterval, dataExtent),
    [alignedTimelineInterval, dataExtent],
  );

  const handleTimeRangeUpdate = useCallback((update) => {
    if (granularity !== 'monthly' && granularity !== 'yearly') {
      return;
    }
    const interval = update?.time ?? update;
    if (!interval || interval.length !== 2) {
      return;
    }
    setDragSelection(
      snapIntervalToTickValues(interval, tickValues, alignedTimelineInterval),
    );
  }, [granularity, tickValues, alignedTimelineInterval]);

  const handleTimeRangeChange = (interval) => {
    setDragSelection(null);
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
    <Box
      sx={{
        marginBottom: 3,
        width: '100%',
        mx: { xs: -2, sm: -4 },
        px: { xs: 2, sm: 4 },
        boxSizing: 'border-box',
      }}
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 2,
          width: '100%',
          marginBottom: 1,
        }}
      >
        <Box
          className="resaa-timeline-minimap-group"
          sx={{
            display: 'flex',
            alignItems: 'center',
            flex: 1,
            minWidth: 0,
            height: TIMELINE_TOOLBAR_CONTROL_HEIGHT,
            borderRadius: 1,
            border: '1px solid #dde2e8',
            backgroundColor: '#eef1f5',
            overflow: 'hidden',
          }}
        >
          <IconButton
            size="small"
            className="resaa-timeline-minimap-pan"
            disabled={!canPanBackward}
            aria-label={t_i18n('Previous period')}
            onClick={() => onViewportPan(-1)}
            sx={{
              ...minimapPanButtonSx,
              borderRight: '1px solid #dde2e8',
            }}
          >
            <ChevronLeft fontSize="small" />
          </IconButton>
          <ResaaTimelineMinimap
            dataExtent={dataExtent}
            viewportInterval={alignedTimelineInterval}
            items={items}
            onNavigate={onViewportNavigate}
          />
          <IconButton
            size="small"
            className="resaa-timeline-minimap-pan"
            disabled={!canPanForward}
            aria-label={t_i18n('Next period')}
            onClick={() => onViewportPan(1)}
            sx={{
              ...minimapPanButtonSx,
              borderLeft: '1px solid #dde2e8',
            }}
          >
            <ChevronRight fontSize="small" />
          </IconButton>
        </Box>
        <ToggleButtonGroup
          size="small"
          exclusive
          value={granularity}
          onChange={handleGranularityChange}
          aria-label={t_i18n('Time step')}
          className="resaa-timeline-granularity-toggle"
          sx={{
            flexShrink: 0,
            height: TIMELINE_TOOLBAR_CONTROL_HEIGHT,
            overflow: 'hidden',
            borderRadius: '6px',
            '& .MuiToggleButton-root': {
              borderRadius: 0,
            },
            '& .MuiToggleButton-root:first-of-type': {
              borderRadius: '6px 0 0 6px',
            },
            '& .MuiToggleButton-root:last-of-type': {
              borderRadius: '0 6px 6px 0',
            },
          }}
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
          height: TIMELINE_SECTION_HEIGHT,
          width: '100%',
          overflow: 'visible',
        }}
      >
        <Box
          sx={{
            position: 'absolute',
            top: TIMELINE_RAIL_TOP_OFFSET,
            insetInlineStart: 0,
            insetInlineEnd: 0,
            height: TIMELINE_RAIL_BAND_HEIGHT,
            pointerEvents: 'none',
          }}
        >
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart
              height={TIMELINE_RAIL_BAND_HEIGHT}
              margin={{
                top: SCATTER_MARGIN_TOP,
                bottom: 0,
                insetInlineStart: 0,
                insetInlineEnd: 0,
              }}
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
            top: TIMELINE_RAIL_TOP_OFFSET,
            insetInlineStart: 0,
            insetInlineEnd: 0,
            bottom: 0,
          }}
        >
          <TimeRange
            key={granularity}
            ticksNumber={tickValues.length || 1}
            tickValues={tickValues}
            showUnitTickMarkers
            tickLabelEvery={tickLabelEvery}
            selectedInterval={displaySelectedInterval}
            timelineInterval={alignedTimelineInterval}
            step={step}
            onUpdateCallback={granularity === 'monthly' || granularity === 'yearly'
              ? handleTimeRangeUpdate
              : () => null}
            onChangeCallback={handleTimeRangeChange}
            formatTick={formatTick}
            tickLabelMultiline
            containerClassName="timerange resaa-timeline-timerange resaa-timeline-timerange--stacked-labels react_time_range__time_range_container"
          />
        </Box>
      </Box>
    </Box>
  );
};

export default ResaaTimelineTimeRangeFilter;
