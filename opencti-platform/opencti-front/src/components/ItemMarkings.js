import React from 'react';
import * as R from 'ramda';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import Chip from '@mui/material/Chip';
import { compose } from 'ramda';
import { truncate } from '../utils/String';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    margin: '0 7px 7px 0',
    borderRadius: '0',
    width: 90,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    marginRight: 7,
    borderRadius: '0',
    width: 90,
  },
});

const inlineStylesDark = {
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

const inlineStylesLight = {
  white: {
    backgroundColor: '#ffffff',
    color: '#2b2b2b',
    border: '1px solid #2b2b2b',
  },
  green: {
    backgroundColor: '#2e7d32',
    color: '#ffffff',
  },
  blue: {
    backgroundColor: '#283593',
    color: '#ffffff',
  },
  red: {
    backgroundColor: '#c62828',
    color: '#ffffff',
  },
  orange: {
    backgroundColor: '#d84315',
    color: '#ffffff',
  },
};

const ItemMarkings = (props) => {
  const { classes, variant, markingDefinitions, limit, theme } = props;
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
          let backgroundColor = markingDefinition.x_opencti_color;
          let textColor = theme.palette.text.primary;
          let border = '0';
          if (theme.palette.mode === 'light') {
            if (backgroundColor === '#ffffff') {
              backgroundColor = '#ffffff';
              textColor = '#2b2b2b';
              border = '1px solid #2b2b2b';
            } else {
              textColor = '#ffffff';
            }
          } else if (backgroundColor === '#ffffff') {
            textColor = '#2b2b2b';
          }
          return (
            <Chip
              key={markingDefinition.definition}
              className={className}
              style={{
                backgroundColor,
                color: textColor,
                border,
              }}
              label={label}
            />
          );
        }
        let inlineStyles = inlineStylesDark;
        if (theme.palette.mode === 'light') {
          inlineStyles = inlineStylesLight;
        }
        switch (markingDefinition.definition) {
          case 'CD':
          case 'CD-SF':
          case 'DR':
          case 'DR-SF':
          case 'TLP:RED':
            return (
              <Chip
                key={markingDefinition.definition}
                className={className}
                style={inlineStyles.red}
                label={label}
              />
            );
          case 'TLP:AMBER':
            return (
              <Chip
                key={markingDefinition.definition}
                className={className}
                style={inlineStyles.orange}
                label={label}
              />
            );
          case 'NP':
          case 'TLP:GREEN':
            return (
              <Chip
                key={markingDefinition.definition}
                className={className}
                style={inlineStyles.green}
                label={label}
              />
            );
          case 'SF':
            return (
              <Chip
                key={markingDefinition.definition}
                className={className}
                style={inlineStyles.blue}
                label={label}
              />
            );
          default:
            return (
              <Chip
                key={markingDefinition.definition}
                className={className}
                style={inlineStyles.white}
                label={label}
              />
            );
        }
      })}
    </div>
  );
};

ItemMarkings.propTypes = {
  theme: PropTypes.object,
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  limit: PropTypes.number,
  markingDefinitions: PropTypes.array,
};

export default compose(withTheme, withStyles(styles))(ItemMarkings);
