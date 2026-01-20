import { CloseOutlined } from '@mui/icons-material';
import { Chip, ChipProps, SxProps, Theme, Tooltip, alpha, useTheme } from '@mui/material';
import React, { CSSProperties } from 'react';

interface TagProps extends Omit<ChipProps, 'color'> {
  label: string;
  color?: string;
  onClick?: (e: React.MouseEvent) => void;
  onDelete?: () => void;
  maxWidth?: number | string;
  icon?: React.ReactElement;
  tooltipTitle?: string;
  disableTooltip?: boolean;
  applyLabelTextTransform?: boolean;
}

const Tag = ({
  label,
  color,
  onClick,
  onDelete,
  maxWidth = '100%',
  icon,
  tooltipTitle,
  disableTooltip = false,
  applyLabelTextTransform = true,
  sx,
  ...chipProps
}: TagProps) => {
  const theme = useTheme();
  const defaultColor = theme.palette.severity?.default ?? '#1C2F49';

  const applyAlpha = color && color !== defaultColor;

  const chipStyle: CSSProperties = {
    borderRadius: 4,
    height: 25,
    fontSize: 12,
    fontWeight: 400,
    paddingLeft: '8px',
    cursor: onClick ? 'pointer' : 'default',
    textTransform: 'capitalize',
  };

  const sxStyles: SxProps<Theme> = {
    backgroundColor: applyAlpha ? alpha(color ?? defaultColor, 0.2) : defaultColor,
    maxWidth: typeof maxWidth === 'number' ? `${maxWidth}px` : maxWidth,
    '& .MuiChip-label': {
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap',
      display: 'block',
      paddingLeft: icon ? '8px' : '4px',
      paddingRight: onDelete ? '4px' : '12px',
      textTransform: applyLabelTextTransform ? 'inherit' : 'none',
    },
    ...(icon && {
      '& .MuiChip-icon': {
        color: color,
      },
    }),
    '& .MuiChip-deleteIcon': {
      color: '#F2F2F3',
      fontSize: 18,
      '&:hover': {
        color: '#FFFFFF',
      },
      background: 'none',
      marginLeft: '8px',
    },
    ...sx,
  };

  const chip = (
    <Chip
      label={label}
      icon={icon}
      onClick={onClick}
      onDelete={onDelete}
      style={chipStyle}
      sx={sxStyles}
      deleteIcon={<CloseOutlined />}
      {...chipProps}
    />
  );

  if (disableTooltip) {
    return chip;
  }

  return (
    <Tooltip title={tooltipTitle ?? label} placement="bottom-start">
      {chip}
    </Tooltip>
  );
};

export default Tag;
