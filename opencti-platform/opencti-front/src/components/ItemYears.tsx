import React from 'react';
import { CSSProperties } from '@mui/styles/withStyles';
import { EMPTY_VALUE } from '../utils/String';
import Tag from '@common/tag/Tag';

interface ItemYearsProps {
  years: string;
}

const ItemYears = ({ years }: ItemYearsProps) => {
  const chipStyle: CSSProperties = {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    marginRight: 8,
  };
  return (
    <Tag
      sx={chipStyle}
      label={years === '1970 - 5138' ? EMPTY_VALUE : years}
    />
  );
};

export default ItemYears;
