import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import { alpha, useTheme } from '@mui/material';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 130,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 130,
  },
});

class TaskStatus extends Component {
  render() {
    const { classes, label, status, variant } = this.props;
    const style = variant === 'inList' ? classes.chipInList : classes.chip;
    const theme = useTheme();
    const inlineStyles = {
      white: {
        backgroundColor: theme.palette.common.white,
        color: theme.palette.common.grey,
      },
      green: {
        backgroundColor: alpha(theme.palette.success.main, 0.08),
        color: theme.palette.success.main,
      },
      blue: {
        backgroundColor: alpha(theme.palette.severity.info, 0.08),
        color: theme.palette.severity.info,
      },
      grey: {
        backgroundColor: alpha(theme.palette.common.grey, 0.08),
        color: theme.palette.common.grey,
      },
      orange: {
        backgroundColor: alpha(theme.palette.severity.high, 0.08),
        color: theme.palette.severity.high,
      },
    };
    switch (status) {
      case 'progress':
      case 'provisioning':
      case 'processing':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.orange}
            label={label}
          />
        );
      case 'wait':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blue}
            label={label}
          />
        );
      case 'complete':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.green}
            label={label}
          />
        );
      default:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blue}
            label={label}
          />
        );
    }
  }
}

TaskStatus.propTypes = {
  classes: PropTypes.object.isRequired,
  status: PropTypes.string,
  label: PropTypes.string,
  variant: PropTypes.string,
};

export default withStyles(styles)(TaskStatus);
