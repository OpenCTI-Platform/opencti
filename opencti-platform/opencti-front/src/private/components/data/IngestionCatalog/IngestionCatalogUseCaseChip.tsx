import { Tooltip } from '@mui/material';
import Chip from '@mui/material/Chip';
import React from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';

interface IngestionCatalogChipProps {
  label: string;
  tooltipLabel?: string;
  variant?: 'outlined' | 'filled';
  color?: 'primary' | 'secondary' | 'error' | 'success';
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
        color={'info'}
        sx={{
          fontSize: 12,
          lineHeight: '14px',
          borderRadius: 1,
          marginRight: isInlist ? theme.spacing(1) : 0,
          border: `1px solid ${theme.palette.primary.dark}`,
        }}
        label={label}
      />
    </Tooltip>
  );
};

export default IngestionCatalogChip;
