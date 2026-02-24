import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import { isEmptyField } from '../utils/utils';
import { useTheme } from '@mui/styles';
import Tag from '@common/tag/Tag';
import { EMPTY_VALUE } from '../utils/String';
import { Theme } from './Theme';

interface ItemScoreProps {
  score?: number | null;
}

const ItemScore: FunctionComponent<ItemScoreProps> = ({ score }) => {
  const theme = useTheme<Theme>();

  if (isEmptyField(score)) {
    return (
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 8, width: '100%' }}
      >
        {EMPTY_VALUE}
      </Typography>
    );
  }
  if (score <= 20) {
    return (
      <Tag
        color={theme.palette.severity.low}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 50) {
    return (
      <Tag
        color={theme.palette.severity.info}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 75) {
    return (
      <Tag
        color={theme.palette.severity.high}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 100) {
    return (
      <Tag
        color={theme.palette.severity.critical}
        label={`${score} / 100`}
      />
    );
  }
  return (
    <Tag
      color={theme.palette.common.grey}
      label={`${score} / 100`}
    />
  );
};

export default ItemScore;
