import React from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import { compose } from 'ramda';
import CircularProgress from '@mui/material/CircularProgress';
import { useTheme } from '@mui/styles';
import inject18n from './i18n';

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
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 100,
  },
});

const computeInlineStyles = (theme) => ({
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
  },
  blue: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
  },
  ee: {
    backgroundColor: theme.palette.ee.lightBackground,
    color: theme.palette.ee.main,
  },
});

const renderChip = (props) => {
  const { classes, label, neutralLabel, status, variant, t, reverse } = props;
  const theme = useTheme();
  let style = classes.chip;
  if (variant === 'inList') {
    style = classes.chipInList;
  } else if (variant === 'large') {
    style = classes.chipLarge;
  }
  const inlineStyles = computeInlineStyles(theme);
  if (status === true) {
    return (
      <Chip
        classes={{ root: style }}
        style={reverse ? inlineStyles.red : inlineStyles.green}
        label={label}
      />
    );
  }
  if (status === null) {
    return (
      <Chip
        classes={{ root: style }}
        style={inlineStyles.blue}
        label={neutralLabel || t('Not applicable')}
      />
    );
  }
  if (status === 'ee') {
    return (
      <Chip
        classes={{ root: style }}
        style={inlineStyles.ee}
        label={neutralLabel || t('EE')}
      />
    );
  }
  if (status === undefined) {
    return (
      <Chip
        classes={{ root: style }}
        style={inlineStyles.blue}
        label={<CircularProgress size={10} color="primary" />}
      />
    );
  }
  return (
    <Chip
      classes={{ root: style }}
      style={reverse ? inlineStyles.green : inlineStyles.red}
      label={label}
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
