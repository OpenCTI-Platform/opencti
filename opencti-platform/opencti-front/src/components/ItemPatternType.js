import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import { compose } from 'ramda';
import inject18n from './i18n';

const styles = () => ({
  chip: {
    fontSize: 15,
    lineHeight: '18px',
    height: 30,
    margin: '0 7px 7px 0',
    borderRadius: 5,
    width: 130,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    marginRight: 7,
    borderRadius: 5,
    width: 80,
  },
});

const inlineStyles = {
  stix: {
    backgroundColor: 'rgba(32, 58, 246, 0.08)',
    color: '#203af6',
    border: '1px solid #203af6',
  },
  pcre: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
    border: '1px solid #5c7bf5',
  },
  sigma: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
    border: '1px solid #4caf50',
  },
  snort: {
    backgroundColor: 'rgba(78, 52, 46, 0.08)',
    color: '#4e342e',
    border: '1px solid #4e342e',
  },
  suricata: {
    backgroundColor: 'rgba(0, 105, 92, 0.08)',
    color: '#00695c',
    border: '1px solid #00695c',
  },
  yara: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
    border: '1px solid #f44336',
  },
  'tanium-signal': {
    backgroundColor: 'rgba(243, 25, 25, 0.08)',
    color: '#f31919',
    border: '1px solid #f31919',
  },
};

class ItemPatternType extends Component {
  render() {
    const {
      classes, variant, label, t,
    } = this.props;
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
            label={label}
          />
        );
      case 'pcre':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.pcre}
            label={label}
          />
        );
      case 'sigma':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.sigma}
            label={label}
          />
        );
      case 'snort':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.snort}
            label={label}
          />
        );
      case 'suricata':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.suricata}
            label={label}
          />
        );
      case 'yara':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.yara}
            label={label}
          />
        );
      case 'tanium-signal':
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles['tanium-signal']}
            label={label}
          />
        );
      default:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.stix}
            label={t('Unknown')}
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

export default compose(inject18n, withStyles(styles))(ItemPatternType);
