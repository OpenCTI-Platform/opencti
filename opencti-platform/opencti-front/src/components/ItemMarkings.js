import React, { Component } from 'react';
import * as R from 'ramda';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import { truncate } from '../utils/String';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    margin: '0 7px 7px 0',
    borderRadius: 5,
    width: 90,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
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

class ItemMarkings extends Component {
  render() {
    const {
      classes, variant, markingDefinitions, limit,
    } = this.props;
    const className = variant === 'inList' ? classes.chipInList : classes.chip;
    const number = limit || 1;
    const sortBy = R.sortWith([R.descend(R.prop('definition'))]);
    const markings = R.pipe(
      R.map((n) => n.node),
      sortBy,
      R.take(number),
    )(markingDefinitions);
    return (
      <div>
        {markings.map((markingDefinition) => {
          const label = truncate(markingDefinition.definition, 20);
          if (markingDefinition.x_opencti_color) {
            return (
              <Chip
                className={className}
                style={{
                  backgroundColor: markingDefinition.x_opencti_color,
                  color:
                    markingDefinition.x_opencti_color === '#ffffff'
                      ? '#2b2b2b'
                      : 'inherit',
                }}
                label={label}
              />
            );
          }
          switch (markingDefinition.definition) {
            case 'CD':
            case 'CD-SF':
            case 'DR':
            case 'DR-SF':
            case 'TLP:RED':
              return (
                <Chip
                  className={className}
                  style={inlineStyles.red}
                  label={label}
                />
              );
            case 'TLP:AMBER':
              return (
                <Chip
                  className={className}
                  style={inlineStyles.orange}
                  label={label}
                />
              );
            case 'NP':
            case 'TLP:GREEN':
              return (
                <Chip
                  className={className}
                  style={inlineStyles.green}
                  label={label}
                />
              );
            case 'TLP:WHITE':
              return (
                <Chip
                  className={className}
                  style={inlineStyles.white}
                  label={label}
                />
              );
            case 'SF':
              return (
                <Chip
                  className={className}
                  style={inlineStyles.blue}
                  label={label}
                />
              );
            default:
              return (
                <Chip
                  className={className}
                  style={inlineStyles.white}
                  label={label}
                />
              );
          }
        })}
      </div>
    );
  }
}

ItemMarkings.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  limit: PropTypes.number,
  markingDefinitions: PropTypes.array,
};

export default withStyles(styles)(ItemMarkings);
