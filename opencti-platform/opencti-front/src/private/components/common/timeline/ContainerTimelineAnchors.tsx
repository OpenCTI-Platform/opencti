import React from 'react';
import { useIntl } from 'react-intl';
import { useTheme } from '@mui/material/styles';
import { Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useTimelineColors from './useTimelineColors';
import { elapsedBetween, TIMELINE_ANCHOR_KEYS, TIMELINE_ANCHOR_LABELS, type TimelineAnchorKey, toTime } from './timelineUtils';
import type { TimelineChartAnchors } from './ContainerTimelineLanes';

const ANCHOR_HELP: Record<TimelineAnchorKey, string> = {
  first_adversary_activity: 'First event of the adversary lane',
  first_detection: 'First event of the detection lane (security platform sightings, coverage results, hunts, deployments)',
  first_response: 'First event of the response lane',
  containment: 'First containment milestone or completion of a task labelled containment',
  closure: 'Last transition to the final workflow status, while the case stays closed',
};

interface ContainerTimelineAnchorsProps {
  anchors: TimelineChartAnchors;
  // Overview card: a compact list with the time to the minute and the time elapsed since the first adversary activity
  dense?: boolean;
  onAnchorClick?: (time: number) => void;
}

const ellipsis: React.CSSProperties = { whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' };

/** Time elapsed since the first adversary activity, in the two largest units ("2d 22h later"). */
const useElapsedLabel = () => {
  const intl = useIntl();
  const { t_i18n } = useFormatter();
  const unit = (value: number, name: 'day' | 'hour' | 'minute') => intl.formatNumber(value, { style: 'unit', unit: name, unitDisplay: 'narrow' });
  return (origin: number, time: number) => {
    const { sign, days, hours, minutes } = elapsedBetween(origin, time);
    if (sign === 0) return t_i18n('At the same time');
    let duration = unit(minutes, 'minute');
    if (days > 0) duration = `${unit(days, 'day')} ${unit(hours, 'hour')}`;
    else if (hours > 0) duration = `${unit(hours, 'hour')} ${unit(minutes, 'minute')}`;
    return t_i18n(sign > 0 ? '{duration} later' : '{duration} earlier', { values: { duration } });
  };
};

const ContainerTimelineAnchorList = ({ anchors }: { anchors: TimelineChartAnchors }) => {
  const { t_i18n } = useFormatter();
  const intl = useIntl();
  const theme = useTheme();
  const colors = useTimelineColors();
  const elapsedLabel = useElapsedLabel();
  const origin = toTime(anchors?.first_adversary_activity);
  return (
    <div role="list" aria-label={t_i18n('Timeline anchors')} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(0.5) }} data-testid="timeline-anchors">
      {TIMELINE_ANCHOR_KEYS.map((key) => {
        const time = toTime(anchors?.[key]);
        const elapsed = time !== null && origin !== null && key !== 'first_adversary_activity' ? elapsedLabel(origin, time) : null;
        return (
          <Tooltip key={key}>
            <TooltipTrigger asChild>
              <div
                role="listitem"
                style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto minmax(0, auto)', columnGap: theme.spacing(1.5), alignItems: 'baseline' }}
                data-testid={`timeline-anchor-${key}`}
              >
                <Text variant="content-caption" as="span" style={{ ...ellipsis, color: colors.textSecondary }}>
                  {t_i18n(TIMELINE_ANCHOR_LABELS[key])}
                </Text>
                <Text variant="content-compact-medium" as="span" style={time !== null ? ellipsis : { ...ellipsis, color: colors.textSecondary }}>
                  {time !== null
                    ? intl.formatDate(time, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })
                    : t_i18n('Not reached')}
                </Text>
                <Text variant="content-caption" as="span" style={{ ...ellipsis, color: colors.textSecondary, textAlign: 'right' }} data-testid={`timeline-anchor-${key}-elapsed`}>
                  {elapsed}
                </Text>
              </div>
            </TooltipTrigger>
            <TooltipContent>{t_i18n(ANCHOR_HELP[key])}</TooltipContent>
          </Tooltip>
        );
      })}
    </div>
  );
};

/** Per-case anchor timestamps (no aggregated metric): one tile per anchor, empty when not reached yet. */
const ContainerTimelineAnchors = ({ anchors, dense = false, onAnchorClick }: ContainerTimelineAnchorsProps) => {
  const { t_i18n, fldt } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  if (dense) {
    return <ContainerTimelineAnchorList anchors={anchors} />;
  }
  return (
    <div
      role="list"
      aria-label={t_i18n('Timeline anchors')}
      style={{ display: 'grid', gridTemplateColumns: `repeat(${TIMELINE_ANCHOR_KEYS.length}, minmax(0, 1fr))`, gap: theme.spacing(1.25) }}
      data-testid="timeline-anchors"
    >
      {TIMELINE_ANCHOR_KEYS.map((key) => {
        const value = anchors?.[key] ?? null;
        const time = toTime(value);
        const tileStyle: React.CSSProperties = {
          display: 'block',
          width: '100%',
          height: '100%',
          boxSizing: 'border-box',
          border: `1px solid ${colors.grid}`,
          borderRadius: theme.shape.borderRadius,
          padding: theme.spacing(1, 1.25),
          minWidth: 0,
          background: 'none',
          color: 'inherit',
          font: 'inherit',
          textAlign: 'left',
        };
        const tileContent = (
          <>
            <Text variant="content-caption" as="div" style={{ ...ellipsis, color: colors.textSecondary }}>
              {t_i18n(TIMELINE_ANCHOR_LABELS[key])}
            </Text>
            <Text variant="content-base-medium" as="div" style={value ? ellipsis : { ...ellipsis, color: colors.textSecondary }}>
              {value ? fldt(value) : t_i18n('Not reached')}
            </Text>
          </>
        );
        // A reached anchor is a control that moves the view to its time; the list semantics stay on the wrapper
        const tile = time !== null && onAnchorClick ? (
          <button type="button" style={{ ...tileStyle, cursor: 'pointer' }} onClick={() => onAnchorClick(time)} data-testid={`timeline-anchor-${key}`}>
            {tileContent}
          </button>
        ) : (
          <div style={tileStyle} data-testid={`timeline-anchor-${key}`}>{tileContent}</div>
        );
        return (
          <div role="listitem" key={key} style={{ minWidth: 0 }}>
            <Tooltip>
              <TooltipTrigger asChild>{tile}</TooltipTrigger>
              <TooltipContent>{t_i18n(ANCHOR_HELP[key])}</TooltipContent>
            </Tooltip>
          </div>
        );
      })}
    </div>
  );
};

export default ContainerTimelineAnchors;
