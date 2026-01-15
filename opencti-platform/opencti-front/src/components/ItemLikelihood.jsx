import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withTheme from '@mui/styles/withTheme';
import Tag from '@common/tag/Tag';
import inject18n from './i18n';

const ItemLikelihood = ({ likelihood, t, theme }) => {
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
      backgroundColor: theme.palette.severity.info,
      color: theme.palette.severity.info,
    },
    red: {
      backgroundColor: theme.palette.error.main,
      color: theme.palette.error.main,
    },
    orange: {
      backgroundColor: theme.palette.severity.high,
      color: theme.palette.severity.high,
    },
  };

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
