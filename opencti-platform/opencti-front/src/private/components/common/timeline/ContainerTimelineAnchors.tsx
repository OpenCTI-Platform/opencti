import React from 'react';
import { useTheme } from '@mui/material/styles';
import { Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useTimelineColors from './useTimelineColors';
import { TIMELINE_ANCHOR_KEYS, TIMELINE_ANCHOR_LABELS, type TimelineAnchorKey, toTime } from './timelineUtils';
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
  dense?: boolean;
  onAnchorClick?: (time: number) => void;
}

/** Per-case anchor timestamps (no aggregated metric): one tile per anchor, empty when not reached yet. */
const ellipsis: React.CSSProperties = { whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' };

const ContainerTimelineAnchors = ({ anchors, dense = false, onAnchorClick }: ContainerTimelineAnchorsProps) => {
  const { t_i18n, fldt, nsdt } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  return (
    <div
      role="list"
      aria-label={t_i18n('Timeline anchors')}
      style={{ display: 'grid', gridTemplateColumns: `repeat(${TIMELINE_ANCHOR_KEYS.length}, minmax(0, 1fr))`, gap: theme.spacing(dense ? 0.75 : 1.25) }}
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
          padding: dense ? theme.spacing(0.5, 1) : theme.spacing(1, 1.25),
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
            <Text variant={dense ? 'content-compact-medium' : 'content-base-medium'} as="div" style={ellipsis}>
              {value ? (dense ? nsdt(value) : fldt(value)) : '-'}
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
