import React, { ElementType } from 'react';

interface FiligranIconProps {
  icon: ElementType;
  size: 'small' | 'medium' | 'large' | number; // we also accepts px size
  style?: React.CSSProperties;
}

// MUI sizes
const sizeMap = {
  small: '20px',
  medium: '24px', // default
  large: '35px',
};

const FiligranIcon = ({ icon, size = 'medium', style }: FiligranIconProps) => {
  const Component = icon;

  const iconSize = typeof size === 'string' ? sizeMap[size] : `${size}px`;

  return (
    <Component
      width={iconSize}
      height={iconSize}
      style={style}
    />
  );
};

export default FiligranIcon;
