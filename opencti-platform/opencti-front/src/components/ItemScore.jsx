import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withTheme from '@mui/styles/withTheme';
import Typography from '@mui/material/Typography';
import inject18n from './i18n';
import { isEmptyField } from '../utils/utils';
import { useTheme } from '@mui/styles';
import Tag from '@common/tag/Tag';

const ItemScore = ({ score }) => {
  const theme = useTheme();

  if (isEmptyField(score)) {
    return (
      <Typography
        variant="h3"
        gutterBottom={true}
        style={{ marginTop: 8, width: '100%' }}
      >
        -
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

ItemScore.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  score: PropTypes.number,
};

export default compose(withTheme, inject18n)(ItemScore);
