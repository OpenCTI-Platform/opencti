import { CloseOutlined } from '@mui/icons-material';
import { Chip, ChipProps, SxProps, Theme, Tooltip, alpha, lighten, useTheme } from '@mui/material';
import React, { CSSProperties, ReactElement } from 'react';

interface TagProps extends Omit<ChipProps, 'color'> {
  label?: string | number | ReactElement | null;
  color?: string;
  onClick?: (e: React.MouseEvent) => void;
  onDelete?: (e: React.MouseEvent) => void;
  maxWidth?: number | string;
  icon?: React.ReactElement;
  tooltipTitle?: string;
  disableTooltip?: boolean;
  labelTextTransform?: 'capitalize' | 'uppercase' | 'lowercase' | 'none';
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
  labelTextTransform = 'capitalize',
  sx,
  ...chipProps
}: TagProps) => {
  const theme = useTheme();
  const defaultColor = theme.palette.severity?.default ?? '#004C66';

  const getBackgroundColor = () => {
    if (!color || color === defaultColor) {
      return defaultColor;
    }

    try {
      return alpha(color, 0.2);
    } catch {
      return defaultColor;
    }
  };

  const bgColor = getBackgroundColor();

  const chipStyle: CSSProperties = {
    borderRadius: 4,
    fontSize: 12,
    fontWeight: 400,
    paddingLeft: '8px',
    cursor: onClick ? 'pointer' : 'default',
    textTransform: labelTextTransform,
  };

  const sxStyles: SxProps<Theme> = {
    backgroundColor: bgColor,
    '&:hover': {
      backgroundColor: onClick ? lighten(bgColor, 0.2) : undefined,
    },
    maxWidth: typeof maxWidth === 'number' ? `${maxWidth}px` : maxWidth,
    height: 25,
    '& .MuiChip-label': {
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap',
      display: 'block',
      paddingLeft: icon ? '8px' : '4px',
      paddingRight: onDelete ? '4px' : '12px',
      textTransform: labelTextTransform,
      '&::first-letter': {
        textTransform: labelTextTransform,
      },
    },
    ...(icon && {
      '& .MuiChip-icon': {
        color: color,
        mr: 0.1,
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
    <Tooltip
      title={tooltipTitle ?? label}
      placement="bottom-start"
      slotProps={{
        tooltip: {
          sx: {
            textTransform: labelTextTransform,
            '&::first-letter': {
              textTransform: labelTextTransform,
            },
          },
        },
      }}
    >
      {chip}
    </Tooltip>
  );
};

export default Tag;
