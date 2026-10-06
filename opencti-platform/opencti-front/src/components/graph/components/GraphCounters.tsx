import React, { useMemo } from 'react';
import { Button, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../i18n';
import type { Theme } from '../../Theme';
import type { GraphBadgeTone } from '../badges/graphBadgeRegistry';
import { buildGraphPalette } from '../utils/graphPalette';

/** One reading of the graph, for example "124 entities", selecting what it counts. */
export interface GraphCounter {
  key: string;
  /** Translated count with its unit. */
  label: string;
  /** Translated description of what a click selects. */
  action: string;
  /** Tone of the badges counted, drawn as a ring next to the count. */
  tone?: GraphBadgeTone;
  onSelect: () => void;
}

export interface GraphCountersProps {
  counters: readonly GraphCounter[];
}

/**
 * The counters opening the graph toolbar: what the graph holds at a glance, each counter selecting
 * the elements it counts so that they can be framed, opened or acted on together.
 */
const GraphCounters = ({ counters }: GraphCountersProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const palette = useMemo(() => buildGraphPalette(theme), [theme]);
  if (counters.length === 0) return null;
  return (
    <div role="group" aria-label={t_i18n('Graph summary')} style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(0.25), flexShrink: 0 }}>
      {counters.map(({ key, label, action, tone, onSelect }) => (
        <Tooltip key={key}>
          <TooltipTrigger asChild>
            <Button
              type="button"
              priority="tertiary"
              size="md"
              aria-label={`${label} - ${action}`}
              startIcon={tone
                ? <span aria-hidden style={{ width: 10, height: 10, borderRadius: '50%', border: `2px solid ${palette.tones[tone]}` }} />
                : undefined}
              onClick={onSelect}
              style={{ whiteSpace: 'nowrap', fontVariantNumeric: 'tabular-nums' }}
            >
              {label}
            </Button>
          </TooltipTrigger>
          <TooltipContent side="top">{action}</TooltipContent>
        </Tooltip>
      ))}
    </div>
  );
};

export default GraphCounters;
