import { Tooltip } from '@mui/material';
import Chip from '@mui/material/Chip';
import React from 'react';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';

interface IngestionCatalogChipProps {
  label: string;
  tooltipLabel?: string;
  variant?: 'outlined' | 'filled';
  color?: 'primary' | 'secondary' | 'error' | 'success' | 'warning';
  withTooltip?: boolean;
  isInTooltip?: boolean;
  isInlist?: boolean;
}

const IngestionCatalogChip = ({
  label,
  tooltipLabel,
  variant,
  color,
  withTooltip = false,
  isInlist = false,
}: IngestionCatalogChipProps) => {
  const theme = useTheme<Theme>();

  const tooltipContent = withTooltip ? (tooltipLabel || label) : undefined;

  return (
    <Tooltip title={tooltipContent}>
      <Chip
        variant={variant ?? 'outlined'}
        size="small"
        color={color ?? 'default'}
        sx={{
          fontSize: 12,
          lineHeight: '14px',
          borderRadius: 1,
          marginRight: isInlist ? theme.spacing(1) : 0,
          border: `1px solid ${color || theme.palette.chip.main}`,
          backgroundColor: 'rgba(0, 0, 0, 0.1)',
        }}
        label={label}
      />
    </Tooltip>
  );
};

export default IngestionCatalogChip;
