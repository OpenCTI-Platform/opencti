import React from 'react';
import { CSSProperties } from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import { EMPTY_VALUE } from '../utils/String';

interface ItemYearsProps {
  years: string;
  variant?: string;
  disabled?: boolean;
}

const ItemYears = ({ years, variant, disabled }: ItemYearsProps) => {
  const chipStyle: CSSProperties = variant === 'inList'
    ? {
        fontSize: 12,
        lineHeight: '12px',
        height: 20,
        marginRight: 15,
      }
    : {
        fontSize: 12,
        lineHeight: '12px',
        height: 25,
        marginRight: 7,
      };
  return (
    <Chip
      sx={chipStyle}
      color={disabled ? 'default' : 'secondary'}
      label={years === '1970 - 5138' ? EMPTY_VALUE : years}
    />
  );
};

export default ItemYears;
