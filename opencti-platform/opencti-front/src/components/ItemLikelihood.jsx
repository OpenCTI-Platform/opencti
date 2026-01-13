import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withTheme from '@mui/styles/withTheme';
import Tag from '@common/tag/Tag';
import inject18n from './i18n';

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

const ItemLikelihood = ({ likelihood, t, theme }) => {
  if (!likelihood) {
    return (
      <Tag
        style={
          theme.palette.mode === 'dark'
            ? inlineStyles.white
            : inlineStyles.whiteLight
        }
        label={t('Unknown')}
      />
    );
  }
  if (likelihood <= 20) {
    return (
      <Tag
        style={inlineStyles.red}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 50) {
    return (
      <Tag
        color={inlineStyles.orange.color}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 75) {
    return (
      <Tag
        style={inlineStyles.blue}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 100) {
    return (
      <Tag
        style={inlineStyles.green}
        label={`${likelihood} / 100`}
      />
    );
  }
  return (
    <Tag
      style={inlineStyles.white}
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
)(ItemLikelihood);
