import { useMemo, useState } from 'react';
import useContainerWidth from './useContainerWidth';
import { useNavigate } from 'react-router-dom';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import { useTheme } from '@mui/material/styles';
import { scaleTime } from 'd3-scale';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { itemColor } from '../../utils/Colors';
import { resolveLink } from '../../utils/Entity';
import { truncate } from '../../utils/String';
import useTimeAxisZoom from './useTimeAxisZoom';
import { CorrelationSource, CorrelationTarget } from './correlationTimelineModel';

interface CorrelationTimelineGraphProps {
  sources: CorrelationSource[];
  targets: CorrelationTarget[];
  // Header of the left column: "Objects of this incident", "Objects of this
  // report"... depends on the entity the view is opened from.
  sourcesLabel: string;
}

const LABEL_WIDTH = 260;
const ROW_HEIGHT = 30;
const TOP_PADDING = 28;
const AXIS_HEIGHT = 56;
const RIBBON_WIDTH = 3;
const DAY = 24 * 60 * 60 * 1000;

// Recency is encoded twice: position on the axis, and opacity.
// Buckets rather than a linear ramp, so that "fresh" stays readable
// even when the time domain spans several years.
const recencyOpacity = (date: Date, now: number) => {
  const ageDays = (now - date.getTime()) / DAY;
  if (ageDays <= 30) return 0.95;
  if (ageDays <= 90) return 0.75;
  if (ageDays <= 365) return 0.5;
  return 0.3;
};

const CorrelationTimelineGraph = ({
  sources,
  targets,
  sourcesLabel,
}: CorrelationTimelineGraphProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, nsd, rd } = useFormatter();
  const navigate = useNavigate();
  const { ref, width } = useContainerWidth();
  const [hoveredSource, setHoveredSource] = useState<string | null>(null);
  const [hoveredTarget, setHoveredTarget] = useState<string | null>(null);

  // Frozen once per mount, so that memoized layouts stay stable across renders.
  const now = useMemo(() => Date.now(), []);
  const plotStart = LABEL_WIDTH + 60;
  const plotEnd = Math.max(plotStart + 200, width - 220);
  const rows = Math.max(sources.length, targets.length);
  const axisY = TOP_PADDING + rows * ROW_HEIGHT + 12;
  const height = axisY + AXIS_HEIGHT;

  // Full time extent of the data, and the currently displayed window.
  // `null` means "everything", so a data change resets the view naturally.
  const fullExtent = useMemo<[number, number]>(() => {
    const dates = targets.map((target) => target.date.getTime());
    const min = dates.length > 0 ? Math.min(...dates) : now - 365 * DAY;
    const max = dates.length > 0 ? Math.max(...dates) : now;
    // Avoid a degenerate domain when every target shares the same date.
    const span = Math.max(max - min, 30 * DAY);
    return [min - span * 0.04, max + span * 0.04];
  }, [targets, now]);

  const { domain, isZoomed, resetZoom } = useTimeAxisZoom({
    ref,
    fullExtent,
    plotStart,
    plotEnd,
  });

  const xScale = useMemo(
    () => scaleTime()
      .domain([new Date(domain[0]), new Date(domain[1])])
      .range([plotStart, plotEnd]),
    [domain, plotStart, plotEnd],
  );

  const sourceY = useMemo(() => {
    const positions = new Map<string, number>();
    sources.forEach((source, index) => {
      positions.set(source.id, TOP_PADDING + index * ROW_HEIGHT);
    });
    return positions;
  }, [sources]);

  const targetY = useMemo(() => {
    const positions = new Map<string, number>();
    targets.forEach((target, index) => {
      positions.set(target.id, TOP_PADDING + index * ROW_HEIGHT);
    });
    return positions;
  }, [targets]);

  // Which elements are emphasized given the current hover.
  const activeSources = useMemo(() => {
    if (hoveredSource) return new Set([hoveredSource]);
    if (hoveredTarget) {
      const target = targets.find((current) => current.id === hoveredTarget);
      return new Set(target?.sourceIds ?? []);
    }
    return null;
  }, [hoveredSource, hoveredTarget, targets]);

  const activeTargets = useMemo(() => {
    if (hoveredTarget) return new Set([hoveredTarget]);
    if (hoveredSource) {
      const source = sources.find((current) => current.id === hoveredSource);
      return new Set(source?.targetIds ?? []);
    }
    return null;
  }, [hoveredSource, hoveredTarget, sources]);

  const isDimmed = (sourceId: string | null, targetId: string | null) => {
    if (!activeSources && !activeTargets) return false;
    const sourceOk = sourceId ? activeSources?.has(sourceId) : true;
    const targetOk = targetId ? activeTargets?.has(targetId) : true;
    return !(sourceOk && targetOk);
  };

  const goTo = (entityType: string, id: string) => {
    const link = resolveLink(entityType);
    if (link) navigate(`${link}/${id}`);
  };

  const sourcesById = useMemo(
    () => new Map(sources.map((source) => [source.id, source])),
    [sources],
  );

  // Rows keep their position when zooming: only the targets falling outside the
  // window stop being drawn, so nothing jumps around under the cursor.
  const visibleTargets = useMemo(
    () => targets.filter((target) => {
      const time = target.date.getTime();
      return time >= domain[0] && time <= domain[1];
    }),
    [targets, domain],
  );
  const visibleSourceIds = useMemo(
    () => new Set(visibleTargets.flatMap((target) => target.sourceIds)),
    [visibleTargets],
  );
  const hiddenTargets = targets.length - visibleTargets.length;

  const ribbons = useMemo(() => {
    const paths: {
      key: string;
      d: string;
      color: string;
      opacity: number;
      sourceId: string;
      targetId: string;
    }[] = [];
    visibleTargets.forEach((target) => {
      const x1 = xScale(target.date);
      const y1 = targetY.get(target.id) ?? 0;
      const opacity = recencyOpacity(target.date, now);
      target.sourceIds.forEach((sourceId) => {
        const source = sourcesById.get(sourceId);
        const y0 = sourceY.get(sourceId);
        if (!source || y0 === undefined) return;
        const x0 = LABEL_WIDTH;
        const dx = (x1 - x0) * 0.45;
        paths.push({
          key: `${sourceId}-${target.id}`,
          d: `M ${x0} ${y0} C ${x0 + dx} ${y0}, ${x1 - dx} ${y1}, ${x1 - 8} ${y1}`,
          color: itemColor(source.entityType),
          opacity,
          sourceId,
          targetId: target.id,
        });
      });
    });
    return paths;
  }, [visibleTargets, sourcesById, xScale, sourceY, targetY, now]);

  const todayX = xScale(new Date(now));
  const showToday = todayX >= plotStart && todayX <= plotEnd;

  if (sources.length === 0 || targets.length === 0) {
    return (
      <div ref={ref} style={{ padding: theme.spacing(4), textAlign: 'center', color: theme.palette.text?.secondary }}>
        {t_i18n('No correlation found with the current settings')}
      </div>
    );
  }

  return (
    <div ref={ref} style={{ width: '100%', overflowX: 'hidden' }}>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          minHeight: 30,
          color: 'text.secondary',
          fontSize: 11,
        }}
      >
        {isZoomed ? (
          <>
            <span>
              {`${nsd(new Date(domain[0]))} → ${nsd(new Date(domain[1]))}`}
              {hiddenTargets > 0 && ` · ${hiddenTargets} ${t_i18n('targets outside the window')}`}
            </span>
            <Button size="small" onClick={resetZoom} sx={{ textTransform: 'none' }}>
              {t_i18n('Reset zoom')}
            </Button>
          </>
        ) : (
          <span>{t_i18n('Pinch or Ctrl + scroll to zoom the time axis, swipe horizontally to pan')}</span>
        )}
      </Box>
      <svg
        width={width}
        height={height}
        role="img"
        aria-label={t_i18n('Correlation timeline')}
      >
        <text
          x={LABEL_WIDTH}
          y={14}
          textAnchor="end"
          fill={theme.palette.text?.secondary}
          fontSize={10}
        >
          {sourcesLabel}
        </text>
        <text x={plotStart} y={14} fill={theme.palette.text?.secondary} fontSize={10}>
          {t_i18n('Correlated containers and entities, positioned by date')}
        </text>

        {/* Ribbons are drawn first so that nodes stay on top. */}
        <g>
          {ribbons.map((ribbon) => (
            <path
              key={ribbon.key}
              d={ribbon.d}
              fill="none"
              stroke={ribbon.color}
              strokeWidth={RIBBON_WIDTH}
              strokeLinecap="round"
              opacity={isDimmed(ribbon.sourceId, ribbon.targetId) ? 0.05 : ribbon.opacity}
              style={{ transition: 'opacity 120ms' }}
            />
          ))}
        </g>

        {/* Left column: objects of the viewed entity */}
        <g>
          {sources.map((source) => {
            const y = sourceY.get(source.id) ?? 0;
            // Dimmed either by hover, or because the zoom left it with no
            // target in view.
            const dimmed = isDimmed(source.id, null) || !visibleSourceIds.has(source.id);
            return (
              <g
                key={source.id}
                onMouseEnter={() => setHoveredSource(source.id)}
                onMouseLeave={() => setHoveredSource(null)}
                onClick={() => goTo(source.entityType, source.id)}
                style={{ cursor: 'pointer' }}
                opacity={dimmed ? 0.25 : 1}
              >
                <rect x={0} y={y - 13} width={LABEL_WIDTH} height={26} fill="transparent" />
                <circle cx={LABEL_WIDTH - 8} cy={y} r={4} fill={itemColor(source.entityType)} />
                <text
                  x={LABEL_WIDTH - 20}
                  y={y + 4}
                  textAnchor="end"
                  fill={theme.palette.text?.primary}
                  fontSize={12}
                >
                  {truncate(source.label, 32)}
                </text>
                <title>
                  {`${t_i18n(source.entityType)} · ${source.label}\n${source.targetIds.length} ${t_i18n('correlated containers')} / ${source.containersTotal} ${t_i18n('in the platform')}`}
                </title>
              </g>
            );
          })}
        </g>

        {/* Right column: correlated containers on the time axis */}
        <g>
          {visibleTargets.map((target) => {
            const x = xScale(target.date);
            const y = targetY.get(target.id) ?? 0;
            const dimmed = isDimmed(null, target.id);
            const radius = 4 + Math.min(target.sourceIds.length, 6);
            const opacity = recencyOpacity(target.date, now);
            const labelOnLeft = x > plotEnd - 40;
            return (
              <g
                key={target.id}
                onMouseEnter={() => setHoveredTarget(target.id)}
                onMouseLeave={() => setHoveredTarget(null)}
                onClick={() => goTo(target.entityType, target.id)}
                style={{ cursor: 'pointer' }}
                opacity={dimmed ? 0.25 : 1}
              >
                <line
                  x1={x}
                  y1={y + radius}
                  x2={x}
                  y2={axisY}
                  stroke={theme.palette.divider}
                  strokeDasharray="2 4"
                />
                <circle
                  cx={x}
                  cy={y}
                  r={radius}
                  fill={itemColor(target.entityType)}
                  fillOpacity={opacity}
                  stroke={itemColor(target.entityType)}
                  strokeWidth={1}
                />
                <text
                  x={labelOnLeft ? x - radius - 8 : x + radius + 8}
                  y={y + 4}
                  textAnchor={labelOnLeft ? 'end' : 'start'}
                  fill={theme.palette.text?.primary}
                  fontSize={12}
                >
                  {truncate(target.label, 26)}
                </text>
                <title>
                  {`${t_i18n(target.entityType)} · ${target.label}\n${nsd(target.date)} (${rd(target.date)})\n${target.sourceIds.length} ${t_i18n('shared objects')}`}
                </title>
              </g>
            );
          })}
        </g>

        {/* Time axis */}
        <g>
          <line x1={plotStart - 30} y1={axisY} x2={plotEnd + 30} y2={axisY} stroke={theme.palette.divider} />
          {xScale.ticks(6).map((tick) => (
            <g key={tick.toISOString()}>
              <line x1={xScale(tick)} y1={axisY} x2={xScale(tick)} y2={axisY + 5} stroke={theme.palette.divider} />
              <text
                x={xScale(tick)}
                y={axisY + 20}
                textAnchor="middle"
                fill={theme.palette.text?.secondary}
                fontSize={10}
              >
                {nsd(tick)}
              </text>
            </g>
          ))}
          {showToday && (
            <>
              <line
                x1={todayX}
                y1={TOP_PADDING - 14}
                x2={todayX}
                y2={axisY + 8}
                stroke={theme.palette.primary?.main}
                strokeDasharray="4 3"
                opacity={0.5}
              />
              <text
                x={todayX + 4}
                y={axisY + 20}
                fill={theme.palette.primary?.main}
                fontSize={10}
              >
                {t_i18n('Today')}
              </text>
            </>
          )}
        </g>

        {/* Legend */}
        <g>
          <text x={0} y={axisY + 40} fill={theme.palette.text?.secondary} fontSize={10}>
            {t_i18n('Node size = number of shared objects · opacity = recency')}
          </text>
        </g>
      </svg>
    </div>
  );
};

export default CorrelationTimelineGraph;
