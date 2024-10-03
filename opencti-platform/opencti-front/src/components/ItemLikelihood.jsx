import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Chip from '@mui/material/Chip';
import inject18n from './i18n';
import useAuth from '../utils/hooks/useAuth';

const styles = () => ({
  chip: {
    fontSize: 12,
    marginRight: 7,
    borderRadius: 4,
    width: 120,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    borderRadius: 4,
    width: 80,
  },
});

const inlineStyles = {
  white: {
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    color: '#ffffff',
  },
  whiteLight: {
    backgroundColor: 'rgba(0, 0, 0, 0.08)',
    color: '#000000',
  },
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  blue: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
  },
  orange: {
    backgroundColor: 'rgba(255, 152, 0, 0.08)',
    color: '#ff9800',
  },
};

const ItemLikelihood = ({ likelihood, classes, variant, t, theme }) => {
  const { me: { monochrome_labels } } = useAuth();
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  if (!likelihood) {
    return (
      <Chip
        classes={{ root: style }}
        style={
          theme.palette.mode === 'dark'
            ? inlineStyles.white
            : inlineStyles.whiteLight
        }
        label={t('Unknown')}
      />
    );
  }
  let chipStyle = inlineStyles.white;
  if (likelihood <= 20) chipStyle = inlineStyles.red;
  else if (likelihood <= 50) chipStyle = inlineStyles.orange;
  else if (likelihood <= 75) chipStyle = inlineStyles.blue;
  else if (likelihood <= 100) chipStyle = inlineStyles.green;
  return (
    <Chip
      classes={{ root: style }}
      style={{
        color: theme.palette.chip.main,
        backgroundColor: monochrome_labels
          ? theme.palette.background.accent
          : chipStyle.backgroundColor,
      }}
      label={`${likelihood} / 100`}
    />
  );
};

ItemLikelihood.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  likelihood: PropTypes.number,
};

export default compose(
  withTheme,
  inject18n,
  withStyles(styles),
)(ItemLikelihood);
