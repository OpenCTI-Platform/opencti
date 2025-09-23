import React, { ElementType } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../components/Theme';

interface FiligranIconProps {
  icon: ElementType,
  color: 'primary' | 'secondary' | 'error' | 'success' | 'ai'
  size: 'small' | 'medium' | 'large' | number // we also accepts px size
  style?: React.CSSProperties
}

// MUI sizes
const sizeMap = {
  small: '20px',
  medium: '24px', // default
  large: '35px',
};

const FiligranIcon = ({ icon, color, size = 'medium', style }: FiligranIconProps) => {
  const theme = useTheme<Theme>();
  const Component = icon;

  const iconSize = typeof size === 'string' ? sizeMap[size] : `${size}px`;

  return (
    <Component
      color={theme.palette[color].main}
      width={iconSize}
      height={iconSize}
      style={style}
    />
  );
};

export default FiligranIcon;
