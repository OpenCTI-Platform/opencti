import React from 'react';
import { CSSProperties } from '@mui/styles/withStyles';
import { EMPTY_VALUE } from '../utils/String';
import Tag from '@common/tag/Tag';

interface ItemYearsProps {
  years: string;
}

const ItemYears = ({ years }: ItemYearsProps) => {
  return (
    <Tag
      sx={{ marginRight: 8 }}
      label={years === '1970 - 5138' ? EMPTY_VALUE : years}
    />
  );
};

export default ItemYears;
