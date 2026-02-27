import React from 'react';
import Tag from '@common/tag/Tag';
import { useTheme } from '@mui/material/styles';
import { EMPTY_VALUE } from '../utils/String';

interface ItemLikelihoodProps {
  likelihood?: number | null;
}

const ItemLikelihood = ({ likelihood }: ItemLikelihoodProps) => {
  const theme = useTheme();
  if (!likelihood) {
    return <>{EMPTY_VALUE}</>;
  }
  if (likelihood <= 20) {
    return (
      <Tag
        color={theme.palette.severity?.critical}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 50) {
    return (
      <Tag
        color={theme.palette.severity?.high}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 75) {
    return (
      <Tag
        color={theme.palette.severity?.info}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 100) {
    return (
      <Tag
        color={theme.palette.severity?.low}
        label={`${likelihood} / 100`}
      />
    );
  }
  return (
    <Tag
      color={theme.palette.common.white}
      label={`${likelihood} / 100`}
    />
  );
};

export default ItemLikelihood;
