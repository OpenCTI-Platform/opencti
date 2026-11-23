import React from 'react';
import { useTheme } from '@mui/material/styles';
import Tag from '@common/tag/Tag';
import type { Theme } from '../../../../components/Theme';

type PaletteName = 'primary' | 'secondary' | 'error' | 'warning' | 'success' | 'info';

interface IngestionCatalogChipProps {
  label: string;
  tooltipLabel?: string;
  /** Kept for the callers: the design-system chip has a single style (1.13). */
  variant?: 'outlined' | 'filled';
  color?: PaletteName | 'default' | string;
  withTooltip?: boolean;
  isInTooltip?: boolean;
  isInlist?: boolean;
}

const PALETTE_NAMES: string[] = ['primary', 'secondary', 'error', 'warning', 'success', 'info'];

/**
 * A connector type or use case chip of the ingestion catalog, drawn by the design-system
 * Chip (one style everywhere: tone fill and hairline in the tone ink). A palette name
 * resolves to the theme colour, a hex colour is used as is, `default` is the neutral tone.
 * A clipped label shows the design-system Chip's own truncation tooltip; `tooltipLabel`
 * (the hidden use cases of the "+N" chip) is passed to Tag only when it adds something,
 * so a chip never opens two tooltips at once (DS Chip contract RULE-06).
 */
const IngestionCatalogChip = ({
  label,
  tooltipLabel,
  color,
  withTooltip = false,
  isInlist = false,
}: IngestionCatalogChipProps) => {
  const theme = useTheme<Theme>();

  const resolvedColor = color && PALETTE_NAMES.includes(color)
    ? (theme.palette[color as PaletteName] as { main?: string } | undefined)?.main
    : color && color !== 'default' ? color : undefined;

  return (
    <Tag
      label={label}
      color={resolvedColor}
      severity={resolvedColor ? undefined : 'neutral'}
      labelTextTransform="none"
      tooltipTitle={withTooltip && tooltipLabel && tooltipLabel !== label ? tooltipLabel : undefined}
      style={{ marginRight: isInlist ? theme.spacing(1) : 0 }}
    />
  );
};

export default IngestionCatalogChip;
