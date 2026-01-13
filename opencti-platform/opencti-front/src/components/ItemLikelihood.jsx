import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withTheme from '@mui/styles/withTheme';
import Tag from '@common/tag/Tag';
import inject18n from './i18n';
import { alpha } from '@mui/material';

const ItemLikelihood = ({ likelihood, classes, variant, t, theme }) => {
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
      backgroundColor: alpha(theme.palette.severity.info, 0.08),
      color: theme.palette.severity.info,
    },
    red: {
      backgroundColor: alpha(theme.palette.error.main, 0.08),
      color: theme.palette.error.main,
    },
    orange: {
      backgroundColor: alpha(theme.palette.severity.high, 0.08),
      color: theme.palette.severity.high,
    },
  };
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
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
