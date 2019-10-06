import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';

const styles = () => ({
  chip: {
    fontSize: 12,
    height: 25,
    margin: '0 7px 7px 0',
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
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
    const { classes, variant } = this.props;
    const style = variant === 'inList' ? this.props.classes.chipInList : classes.chip;
    if (this.props.color) {
      return (
        <Chip
          classes={{ root: style }}
          style={{
            backgroundColor: this.props.color,
            color: this.props.color === '#ffffff' ? '#2b2b2b' : 'inherit',
          }}
          label={this.props.label}
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
            label={this.props.label}
          />
        );
      case 'TLP:AMBER':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.orange}
            label={this.props.label}
          />
        );
      case 'NP':
      case 'TLP:GREEN':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.green}
            label={this.props.label}
          />
        );
      case 'TLP:WHITE':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.white}
            label={this.props.label}
          />
        );
      case 'SF':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blue}
            label={this.props.label}
          />
        );
      default:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.white}
            label={this.props.label}
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
