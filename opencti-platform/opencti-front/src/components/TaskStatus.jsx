import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 130,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 130,
  },
});

const inlineStyles = {
  white: {
    backgroundColor: '#ffffff',
    color: '#2b2b2b',
  },
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  blue: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
  },
  grey: {
    backgroundColor: 'rgba(96, 125, 139, 0.08)',
    color: '#607d8b',
  },
  orange: {
    backgroundColor: 'rgba(255, 152, 0, 0.08)',
    color: '#ff9800',
  },
};

class TaskStatus extends Component {
  render() {
    const { classes, label, status, variant } = this.props;
    const style = variant === 'inList' ? classes.chipInList : classes.chip;
    switch (status) {
      case 'progress':
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
