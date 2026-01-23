import React from 'react';
import * as PropTypes from 'prop-types';
import Tooltip from '@mui/material/Tooltip';
import { compose } from 'ramda';
import CircularProgress from '@mui/material/CircularProgress';
import { useTheme } from '@mui/styles';
import inject18n from './i18n';
import Tag from '@common/tag/Tag';

const renderTag = (props) => {
  const { label, neutralLabel, status, t, reverse, labelTextTransform } = props;
  const theme = useTheme();

  if (status === true) {
    return (
      <Tag label={label} color={reverse ? theme.palette.error.main : theme.palette.success.main} labelTextTransform={labelTextTransform} />
    );
  }

  if (status === null) {
    return (
      <Tag label={neutralLabel || t('Not applicable')} labelTextTransform={labelTextTransform} />
    );
  }

  if (status === 'ee') {
    return (
      <Tag
        label={neutralLabel || t('EE')}
        color={theme.palette.ee.lightBackground}
        labelTextTransform={labelTextTransform}
      />
    );
  }

  if (status === undefined) {
    return (
      <Tag
        label={<CircularProgress size={10} color="primary" />}
      />
    );
  }

  return (
    <Tag
      label={label}
      color={reverse ? theme.palette.success.main : theme.palette.error.main}
    />
  );
};
const ItemBoolean = (props) => {
  const { tooltip } = props;
  if (tooltip) {
    return (
      <Tooltip title={tooltip}>
        {renderTag(props)}
      </Tooltip>
    );
  }
  return renderTag(props);
};

ItemBoolean.propTypes = {
  classes: PropTypes.object.isRequired,
  status: PropTypes.oneOfType([PropTypes.bool, PropTypes.string]),
  label: PropTypes.string,
  neutralLabel: PropTypes.string,
  variant: PropTypes.string,
  reverse: PropTypes.bool,
  labelTextTransform: PropTypes.string,
};

export default compose(inject18n)(ItemBoolean);
