import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withTheme from '@mui/styles/withTheme';
import Typography from '@mui/material/Typography';
import inject18n from './i18n';
import { isEmptyField } from '../utils/utils';
import { useTheme } from '@mui/styles';
import Tag from '@common/tag/Tag';

const ItemScore = (props) => {
  const theme = useTheme();

  const inlineStyles = {
    white: {
      backgroundColor: theme.palette.common.white,
      color: theme.palette.common.white,
    },
    whiteLight: {
      backgroundColor: theme.palette.common.black,
      color: theme.palette.common.black,
    },
    green: {
      backgroundColor: theme.palette.success.main,
      color: theme.palette.success.main,
    },
    blue: {
      backgroundColor: theme.palette.severity?.info,
      color: theme.palette.severity?.info,
    },
    red: {
      backgroundColor: theme.palette.error.main,
      color: theme.palette.error.main,
    },
    orange: {
      backgroundColor: theme.palette.severity?.high,
      color: theme.palette.severity?.high,
    },
  };

  const { score, classes, variant } = props;
  let style = '';

  if (variant === 'inList' && classes) {
    style = classes.chipInList ?? classes.chip ?? '';
  }
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
        classes={{ root: style }}
        style={inlineStyles.green}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 50) {
    return (
      <Tag
        classes={{ root: style }}
        style={inlineStyles.blue}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 75) {
    return (
      <Tag
        classes={{ root: style }}
        style={inlineStyles.orange}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 100) {
    return (
      <Tag
        classes={{ root: style }}
        style={inlineStyles.red}
        label={`${score} / 100`}
      />
    );
  }
  return (
    <Tag
      classes={{ root: style }}
      style={inlineStyles.white}
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
