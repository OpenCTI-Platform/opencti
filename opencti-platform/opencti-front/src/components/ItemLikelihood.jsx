import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withTheme from '@mui/styles/withTheme';
import Tag from '@common/tag/Tag';
import inject18n from './i18n';

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
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
  },
  red: {
    backgroundColor: alpha(theme.palette.error.main, 0.08),
    color: theme.palette.error.main,
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
