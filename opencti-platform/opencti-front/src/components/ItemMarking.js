import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import { truncate } from '../utils/String';

const styles = () => ({
  chip: {
    fontSize: 12,
    height: 25,
    margin: '0 7px 7px 0',
    borderRadius: 5,
    width: 90,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    marginRight: 7,
    borderRadius: 5,
    width: 90,
  },
});

const inlineStyles = {
  white: {
    backgroundColor: '#ffffff',
    color: '#2b2b2b',
  },
  green: {
    backgroundColor: '#2e7d32',
  },
  blue: {
    backgroundColor: '#283593',
  },
  red: {
    backgroundColor: '#c62828',
  },
  orange: {
    backgroundColor: '#d84315',
  },
};

class ItemMarking extends Component {
  render() {
    const {
      classes, variant, label, color,
    } = this.props;
    const tuncatedLabel = truncate(label, 20);
    const style = variant === 'inList' ? classes.chipInList : classes.chip;
    if (this.props.color) {
      return (
        <Chip
          classes={{ root: style }}
          style={{
            backgroundColor: color,
            color: color === '#ffffff' ? '#2b2b2b' : 'inherit',
          }}
          label={tuncatedLabel}
        />
      );
    }

    switch (this.props.label) {
      case 'CD':
      case 'CD-SF':
      case 'DR':
      case 'DR-SF':
      case 'TLP:RED':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.red}
            label={tuncatedLabel}
          />
        );
      case 'TLP:AMBER':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.orange}
            label={tuncatedLabel}
          />
        );
      case 'NP':
      case 'TLP:GREEN':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.green}
            label={tuncatedLabel}
          />
        );
      case 'TLP:WHITE':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.white}
            label={tuncatedLabel}
          />
        );
      case 'SF':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blue}
            label={tuncatedLabel}
          />
        );
      default:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.white}
            label={tuncatedLabel}
          />
        );
    }
  }
}

ItemMarking.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  label: PropTypes.string,
  color: PropTypes.string,
};

export default withStyles(styles)(ItemMarking);
