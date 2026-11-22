import React, { useRef } from 'react';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import useResizeObserver from '../../../../utils/hooks/useResizeObserver';
import type { TimelineDayBucket } from './irTimelineEvents';

// Horizontal time axis of a requirement: time runs left to right, one lane per kind of event.
// Entries are bubbles sized by their number, score changes are triangles (up or down), decisions squares,
// recalculations diamonds. Clicking a day selects it; clicking it again shows the whole period.
// Compact (preview of the Overview): a single lane, score changes above the entries, decisions and recalculations below.

const LANE_HEIGHT = 46;
const COMPACT_LANE_HEIGHT = 72;
const LABELS = 132;
const RIGHT = 24;
const TOP = 8;
const AXIS = 28;
const DAY = 24 * 3600 * 1000;

interface IrTimelineAxisProps {
  buckets: TimelineDayBucket[];
  start: string; // YYYY-MM-DD, first day of the axis
  end: string; // YYYY-MM-DD, last day of the axis
  selectedDay: string | null;
  onSelectDay: (day: string | null) => void;
  compact?: boolean;
}

const IrTimelineAxis = ({ buckets, start, end, selectedDay, onSelectDay, compact = false }: IrTimelineAxisProps) => {
  const { t_i18n, fsd } = useFormatter();
  const theme = useTheme(); // the MUI theme: its palette colours are resolved strings
  const ref = useRef<HTMLDivElement | null>(null);
  const { width } = useResizeObserver(ref);

  const lanes = [
    { key: 'entry', label: t_i18n('Entries'), total: buckets.reduce((n, b) => n + b.entry, 0) },
    { key: 'score', label: t_i18n('Score changes'), total: buckets.reduce((n, b) => n + b.up + b.down, 0) },
    { key: 'decision', label: t_i18n('Decisions'), total: buckets.reduce((n, b) => n + b.decision, 0) },
    { key: 'config', label: t_i18n('Configuration'), total: buckets.reduce((n, b) => n + b.config, 0) },
  ];
  const LEFT = compact ? 12 : LABELS;
  const laneHeight = compact ? COMPACT_LANE_HEIGHT : LANE_HEIGHT;
  const laneCount = compact ? 1 : lanes.length;
  const height = TOP + laneCount * laneHeight + AXIS;
  const startTime = new Date(`${start}T00:00:00Z`).getTime();
  const endTime = new Date(`${end}T00:00:00Z`).getTime() + DAY;
  const inner = Math.max(width - LEFT - RIGHT, 10);
  const dayWidth = inner / Math.max((endTime - startTime) / DAY, 1);
  const x = (day: string) => LEFT + ((new Date(`${day}T00:00:00Z`).getTime() - startTime + DAY / 2) / (endTime - startTime)) * inner;
  // Compact: everything on one lane, score changes above the entries, decisions and recalculations below
  const OFFSETS = [0, -24, 22, 22];
  const laneY = (index: number) => (compact
    ? TOP + laneHeight / 2 + OFFSETS[index]
    : TOP + index * laneHeight + laneHeight / 2);
  const maxEntries = Math.max(...buckets.map((b) => b.entry), 1);
  const radius = (count: number) => 4 + (compact ? 9 : 11) * Math.sqrt(count / maxEntries);

  // About six date labels, whatever the length of the period
  const totalDays = Math.round((endTime - startTime) / DAY);
  const step = Math.max(1, Math.round(totalDays / (compact ? 4 : 6)));
  const column = Math.max(dayWidth, 16); // clickable width of a day, even on a long period
  const ticks = Array.from({ length: Math.floor((totalDays - 1) / step) + 1 }, (_, i) => new Date(startTime + i * step * DAY).toISOString().slice(0, 10));

  const text = { fontSize: 11, fill: theme.palette.text.secondary, fontFamily: theme.typography.fontFamily };
  const triangle = (cx: number, cy: number, up: boolean) => (up
    ? `${cx - 6},${cy + 5} ${cx},${cy - 6} ${cx + 6},${cy + 5}`
    : `${cx - 6},${cy - 5} ${cx},${cy + 6} ${cx + 6},${cy - 5}`);

  return (
    <Box ref={ref} sx={{ width: '100%' }}>
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={t_i18n('Timeline of the requirement')}>
          {compact && <line x1={LEFT} x2={LEFT + inner} y1={laneY(0)} y2={laneY(0)} stroke={theme.palette.divider} />}
          {!compact && lanes.map((lane, i) => (
            <g key={lane.key}>
              <text x={0} y={laneY(i) + 4} style={{ ...text, fill: theme.palette.text.primary }}>{lane.label}</text>
              <text x={LEFT - 12} y={laneY(i) + 4} textAnchor="end" style={text}>{String(lane.total)}</text>
              <line x1={LEFT} x2={LEFT + inner} y1={laneY(i)} y2={laneY(i)} stroke={theme.palette.divider} />
            </g>
          ))}
          {selectedDay && (
            <rect x={x(selectedDay) - column / 2} y={TOP} width={column} height={laneCount * laneHeight} rx={4} fill={theme.palette.action.selected} />
          )}
          {buckets.map((b) => {
            const cx = x(b.day);
            const r = b.entry > 0 ? radius(b.entry) : 0;
            return (
              <g key={b.day}>
                {b.entry > 0 && (
                  <>
                    <circle cx={cx} cy={laneY(0)} r={r} fill={theme.palette.primary.main} opacity={0.85} />
                    {r >= 9 && <text x={cx} y={laneY(0) + 4} textAnchor="middle" style={{ ...text, fill: theme.palette.primary.contrastText }}>{String(b.entry)}</text>}
                  </>
                )}
                {b.up > 0 && <polygon points={triangle(cx - (b.down > 0 ? 7 : 0), laneY(1), true)} fill={theme.palette.success.main} />}
                {b.down > 0 && <polygon points={triangle(cx + (b.up > 0 ? 7 : 0), laneY(1), false)} fill={theme.palette.error.main} />}
                {b.up + b.down > 1 && (compact
                  ? <text x={cx + (b.up > 0 && b.down > 0 ? 17 : 10)} y={laneY(1) + 4} style={text}>{String(b.up + b.down)}</text>
                  : <text x={cx} y={laneY(1) + 19} textAnchor="middle" style={text}>{String(b.up + b.down)}</text>)}
                {b.decision > 0 && <rect x={cx - 5 - (compact && b.config > 0 ? 7 : 0)} y={laneY(2) - 5} width={10} height={10} rx={2} fill={theme.palette.secondary.main} />}
                {b.config > 0 && <rect x={cx - 5} y={laneY(3) - 5} width={10} height={10} fill={theme.palette.text.secondary} transform={`rotate(45 ${cx + (compact && b.decision > 0 ? 7 : 0)} ${laneY(3)})`} />}
                {/* the whole column of the day is clickable */}
                <rect
                  x={cx - column / 2}
                  y={TOP}
                  width={column}
                  height={laneCount * laneHeight}
                  fill="transparent"
                  style={{ cursor: 'pointer' }}
                  onClick={() => onSelectDay(selectedDay === b.day ? null : b.day)}
                >
                  <title>{`${fsd(b.day)}: ${t_i18n('{count, plural, one {# entry} other {# entries}}', { values: { count: b.entry } })}, ${t_i18n('{count, plural, one {# score change} other {# score changes}}', { values: { count: b.up + b.down } })}, ${t_i18n('{count, plural, one {# decision} other {# decisions}}', { values: { count: b.decision } })}`}</title>
                </rect>
              </g>
            );
          })}
          {ticks.map((day) => {
            const near = x(day) - LEFT < 40; // a label at the very start of the axis is not cut
            return <text key={day} x={near ? LEFT : x(day)} y={height - 8} textAnchor={near ? 'start' : 'middle'} style={text}>{fsd(day)}</text>;
          })}
        </svg>
      )}
    </Box>
  );
};

export default IrTimelineAxis;
