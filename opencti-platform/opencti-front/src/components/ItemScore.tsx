import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import { isEmptyField } from '../utils/utils';
import Tag from '@common/tag/Tag';
import { EMPTY_VALUE } from '../utils/String';
import { scoreTone } from '../utils/severityTone';

interface ItemScoreProps {
  score?: number | null;
}

const ItemScore: FunctionComponent<ItemScoreProps> = ({ score }) => {
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
  return (
    <Tag
      severity={scoreTone(score)}
      label={`${score} / 100`}
    />
  );
};

export default ItemScore;
