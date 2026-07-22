import { Tooltip } from '@mui/material';
import Chip, { ChipProps } from '@mui/material/Chip';
import React from 'react';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';

interface IngestionCatalogChipProps {
  label: string;
  tooltipLabel?: string;
  variant?: 'outlined' | 'filled';
  color?: 'primary' | 'secondary' | 'error' | 'success' | 'warning' | string;
  withTooltip?: boolean;
  isInTooltip?: boolean;
  isInlist?: boolean;
}

interface CustomChipProps extends Omit<ChipProps, 'color'> {
  color?: 'primary' | 'secondary' | 'error' | 'warning' | 'success' | 'info' | 'default' | string;
}

const CustomChip = ({ color, ...props }: CustomChipProps) => {
  const validMuiColors = ['primary', 'secondary', 'error', 'warning', 'success', 'info', 'default'];
  const isMuiColor = color && validMuiColors.includes(color);

  return (
    <Chip
      {...props}
      color={isMuiColor ? (color as ChipProps['color']) : undefined}
      sx={{
        ...(color && !isMuiColor && {
          borderColor: color,
          color,
        }),
        ...props.sx,
      }}
    />
  );
};

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
      <CustomChip
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
          color,
        }}
        label={label}
      />
    </Tooltip>
  );
};

export default IngestionCatalogChip;
