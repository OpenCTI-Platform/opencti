import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import Slide from '@mui/material/Slide';
import Tooltip from '@mui/material/Tooltip';
import inject18n from './i18n';
import { hexToRGB, stringToColour } from '../utils/Colors';
import { truncate } from '../utils/String';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = () => ({
  labels: {
    margin: 0,
    padding: 0,
  },
  label: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 7px 0',
  },
  labelInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    margin: '0 7px 0 0',
  },
  labelInSearch: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 0 0',
  },
  labelInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
});

class StixItemLabels extends Component {
  render() {
    const { classes, labels, t, theme, variant } = this.props;
    let style = classes.label;
    if (variant === 'inList') {
      style = classes.labelInList;
    }
    if (variant === 'inSearch') {
      style = classes.labelInSearch;
    }
    const sortedLabels = R.sort(R.ascend, labels || []);
    return (
      <div className={classes.objectLabel}>
        {sortedLabels.length > 0 ? (
          R.map(
            (label) => (
              <Tooltip key={label} title={label}>
                <Chip
                  variant="outlined"
                  classes={{ root: style }}
                  label={truncate(label, 25)}
                  style={{
                    color: stringToColour(label),
                    borderColor: stringToColour(label),
                    backgroundColor: hexToRGB(stringToColour(label)),
                  }}
                />
              </Tooltip>
            ),
            R.take(3, sortedLabels),
          )
        ) : (
          <Chip
            classes={{ root: style }}
            variant="outlined"
            label={t('No label')}
            style={{
              color: theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
              borderColor:
                theme.palette.mode === 'dark' ? '#ffffff' : '#000000',
              backgroundColor: hexToRGB(
                theme.palette.mode === 'dark' ? '#ffffff' : 'transparent',
              ),
            }}
          />
        )}
      </div>
    );
  }
}

StixItemLabels.propTypes = {
  classes: PropTypes.object.isRequired,
  theme: PropTypes.object,
  t: PropTypes.func,
  variant: PropTypes.string,
  onClick: PropTypes.func,
  labels: PropTypes.array,
};

export default R.compose(inject18n, withTheme, withStyles(styles))(StixItemLabels);
