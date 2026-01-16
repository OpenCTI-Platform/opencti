import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withTheme from '@mui/styles/withTheme';
import Tag from '@common/tag/Tag';
import inject18n from './i18n';

const ItemLikelihood = ({ likelihood, t, theme }) => {
  if (!likelihood) {
    return (
      <Tag
        color={
          theme.palette.mode === 'dark'
            ? theme.palette.common.white
            : theme.palette.common.black
        }
        label={t('Unknown')}
      />
    );
  }
  if (likelihood <= 20) {
    return (
      <Tag
        color={theme.palette.severity.critical}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 50) {
    return (
      <Tag
        color={theme.palette.severity.high}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 75) {
    return (
      <Tag
        color={theme.palette.severity.info}
        label={`${likelihood} / 100`}
      />
    );
  }
  if (likelihood <= 100) {
    return (
      <Tag
        color={theme.palette.severity.low}
        label={`${likelihood} / 100`}
      />
    );
  }
  return (
    <Tag
      color={theme.palette.common.white}
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
