import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Chip from '@mui/material/Chip';
import Typography from '@mui/material/Typography';
import inject18n from './i18n';
import { isEmptyField } from '../utils/utils';
import { alpha, useTheme } from '@mui/material';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'right',
    textTransform: 'uppercase',
    borderRadius: 4,
  },
});

const ItemScore = (props) => {
  const theme = useTheme();

  const inlineStyles = {
    white: {
      backgroundColor: alpha(theme.palette.common.white, 0.08),
      color: theme.palette.common.white,
    },
    whiteLight: {
      backgroundColor: alpha(theme.palette.common.black, 0.08),
      color: theme.palette.common.black,
    },
    green: {
      backgroundColor: alpha(theme.palette.success.main, 0.08),
      color: theme.palette.success.main,
    },
    blue: {
      backgroundColor: alpha(theme.palette.severity?.info || '#4DCCFF', 0.08),
      color: theme.palette.severity?.info || '#4DCCFF',
    },
    red: {
      backgroundColor: alpha(theme.palette.error.main, 0.08),
      color: theme.palette.error.main,
    },
    orange: {
      backgroundColor: alpha(theme.palette.severity?.high || '#E6700F', 0.08),
      color: theme.palette.severity?.high || '#E6700F',
    },
  };

  const { score, classes, variant } = props;
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
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
      <Chip
        classes={{ root: style }}
        style={inlineStyles.green}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 50) {
    return (
      <Chip
        classes={{ root: style }}
        style={inlineStyles.blue}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 75) {
    return (
      <Chip
        classes={{ root: style }}
        style={inlineStyles.orange}
        label={`${score} / 100`}
      />
    );
  }
  if (score <= 100) {
    return (
      <Chip
        classes={{ root: style }}
        style={inlineStyles.red}
        label={`${score} / 100`}
      />
    );
  }
  return (
    <Chip
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

export default compose(withTheme, inject18n, withStyles(styles))(ItemScore);
