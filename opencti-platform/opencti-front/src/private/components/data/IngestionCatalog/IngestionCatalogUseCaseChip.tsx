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
}

const IngestionCatalogChip = ({ label, variant, color, withTooltip = false }: IngestionCatalogChipProps) => {
  const theme = useTheme<Theme>();
  return (
    <Tooltip title={withTooltip ? label : undefined}>
      <Chip
        variant={variant ?? 'outlined'}
        size="small"
        color={color ?? 'default'}
        style={{
          fontSize: 12,
          lineHeight: '12px',
          margin: '7px 7px 7px 0',
          borderRadius: 4,
          border: `2px solid ${color ? theme.palette[color].main : theme.palette.chip.main}`,
        }}
        label={label}
      />
    </Tooltip>
  );
};

export default IngestionCatalogChip;
