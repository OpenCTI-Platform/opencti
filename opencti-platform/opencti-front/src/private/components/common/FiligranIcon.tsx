import React, { ElementType } from 'react';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../components/Theme';

interface FiligranIconProps {
  icon: ElementType,
  color: 'primary' | 'secondary' | 'error' | 'success'
  size: 'small' | 'medium' | 'large'
}

const sizeMap = {
  small: '1rem',
  medium: '1.25rem',
  large: '1.5rem',
};

const FiligranIcon = ({ icon, color, size }: FiligranIconProps) => {
  const theme = useTheme<Theme>();
  const Component = icon;

  return (
    <Component
      color={theme.palette[color].main}
      width={sizeMap[size]}
      height={sizeMap[size]}
    />
  );
};

export default FiligranIcon;
