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
    marginRight: 7,
  },
});

const inlineStyles = {
  stix: {
    backgroundColor: '#283593',
  },
  pcre: {
    backgroundColor: '#4527a0',
  },
  sigma: {
    backgroundColor: '#2e7d32',
  },
  snort: {
    backgroundColor: '#4e342e',
  },
  suricata: {
    backgroundColor: '#00695c',
  },
  yara: {
    backgroundColor: '#c62828',
  },
};

class ItemPatternType extends Component {
  render() {
    const { classes, variant } = this.props;
    const style = variant === 'inList' ? classes.chipInList : classes.chip;
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
      case 'stix':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.stix}
            label={this.props.label}
          />
        );
      case 'pcre':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.pcre}
            label={this.props.label}
          />
        );
      case 'sigma':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.sigma}
            label={this.props.label}
          />
        );
      case 'snort':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.snort}
            label={this.props.label}
          />
        );
      case 'suricata':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.suricata}
            label={this.props.label}
          />
        );
      case 'yara':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.yara}
            label={this.props.label}
          />
        );
      default:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.stix}
            label={this.props.label}
          />
        );
    }
  }
}

ItemPatternType.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  label: PropTypes.string,
  color: PropTypes.string,
};

export default withStyles(styles)(ItemPatternType);
