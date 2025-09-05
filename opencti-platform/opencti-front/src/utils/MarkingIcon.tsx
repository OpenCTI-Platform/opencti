import React from 'react';
import ItemIcon from '../components/ItemIcon';
import type { Theme } from '../components/Theme';

interface MarkingIconProps {
  color: string | undefined | null;
  theme: Theme
}
const MarkingIcon = ({ color, theme }: MarkingIconProps) : React.ReactNode => {
  if (color === 'transparent') {
    const transparentColor = theme.palette.mode === 'light' ? '#2b2b2b' : '#ffffff';
    return (
      <ItemIcon
        type="Marking-Definition"
        color={transparentColor}
      />
    );
  }
  if (theme.palette.mode === 'light' && color === '#ffffff') {
    // White alternative for light mode.
    return (
      <ItemIcon
        type="Marking-Definition"
        color={'#2b2b2b'}
      />
    );
  }
  return (
    <ItemIcon
      type="Marking-Definition"
      color={color}
    />
  );
};

export default MarkingIcon;
