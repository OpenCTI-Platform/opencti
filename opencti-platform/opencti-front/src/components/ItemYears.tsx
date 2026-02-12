import React from 'react';
import { EMPTY_VALUE } from '../utils/String';
import Tag from '@common/tag/Tag';

interface ItemYearsProps {
  years: string;
}

const ItemYears = ({ years }: ItemYearsProps) => {
  return (
    <Tag
      label={years === '1970 - 5138' ? EMPTY_VALUE : years}
    />
  );
};

export default ItemYears;
