import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
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

const ItemMarking = (props) => {
  const { classes, variant, label, color, theme } = props;
  const tuncatedLabel = truncate(label, 20);
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  if (color) {
    let backgroundColor = color;
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
        classes={{ root: style }}
        style={{
          backgroundColor,
          color: textColor,
          border,
        }}
        label={tuncatedLabel}
      />
    );
  }
  let inlineStyles = inlineStylesDark;
  if (theme.palette.mode === 'light') {
    inlineStyles = inlineStylesLight;
  }
  switch (label) {
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
};

ItemMarking.propTypes = {
  theme: PropTypes.object,
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  label: PropTypes.string,
  color: PropTypes.string,
};

export default compose(withTheme, withStyles(styles))(ItemMarking);
