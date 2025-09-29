import { Tooltip } from '@mui/material';
import Chip from '@mui/material/Chip';
import React from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';

interface IngestionCatalogChipProps {
  label: string;
  variant?: 'outlined' | 'filled';
  color?: 'primary' | 'secondary' | 'error' | 'success';
  withTooltip?: boolean;
  isInTooltip?: boolean;
  isInlist?: boolean;
}

const IngestionCatalogChip = ({ label, variant, color, withTooltip = false, isInTooltip = false, isInlist = false }: IngestionCatalogChipProps) => {
  const theme = useTheme<Theme>();
  const width = isInTooltip ? '100%' : 'auto';
  return (
    <Tooltip title={withTooltip ? label : undefined}>
      <Chip
        variant={variant ?? 'outlined'}
        size="small"
        color={color ?? 'default'}
        style={{
          fontSize: 12,
          lineHeight: '14px',
          borderRadius: 4,
          marginRight: isInlist ? theme.spacing(1) : 0,
          border: `2px solid ${color ? theme.palette[color].main : theme.palette.chip.main}`,
          width,
        }}
        label={label}
      />
    </Tooltip>
  );
};

export default IngestionCatalogChip;
