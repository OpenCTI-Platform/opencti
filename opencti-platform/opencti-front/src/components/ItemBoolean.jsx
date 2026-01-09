import React from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import Tooltip from '@mui/material/Tooltip';
import { compose } from 'ramda';
import CircularProgress from '@mui/material/CircularProgress';
import { useTheme } from '@mui/styles';
import inject18n from './i18n';
import { chipInListBasicStyle } from '../utils/chipStyle';
import Tag from '@common/tag/Tag';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 120,
  },
  chipLarge: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 150,
  },
  chipxLarge: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 250,
  },
  chipHigh: {
    fontSize: 12,
    lineHeight: '12px',
    height: 38,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 150,
  },
  chipInList: {
    ...chipInListBasicStyle,
    lineHeight: '12px',
    textTransform: 'uppercase',
    width: 100,
  },
});

const renderChip = (props) => {
  const { label, neutralLabel, status, t, reverse } = props;
  const theme = useTheme();

  if (status === true) {
    return (
      <Tag label={label} color={reverse ? '#f44336' : '#4caf50'} />
    );
  }

  if (status === null) {
    return (
      <Tag label={neutralLabel || t('Not applicable')} />
    );
  }

  if (status === 'ee') {
    return (
      <Tag
        label={neutralLabel || t('EE')}
        color={theme.palette.ee.lightBackground}
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
      color={reverse ? '#4caf50' : '#f44336'}
    />
  );
};
const ItemBoolean = (props) => {
  const { tooltip } = props;
  if (tooltip) {
    return (
      <Tooltip title={tooltip}>
        {renderChip(props)}
      </Tooltip>
    );
  }
  return renderChip(props);
};

ItemBoolean.propTypes = {
  classes: PropTypes.object.isRequired,
  status: PropTypes.oneOfType([PropTypes.bool, PropTypes.string]),
  label: PropTypes.string,
  neutralLabel: PropTypes.string,
  variant: PropTypes.string,
  reverse: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(ItemBoolean);
