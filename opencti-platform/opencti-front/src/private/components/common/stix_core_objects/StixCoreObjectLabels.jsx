import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, take } from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import inject18n from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';
import { truncate } from '../../../../utils/String';

const styles = () => ({
  labels: {
    margin: 0,
    padding: 0,
  },
  label: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 7px 0',
    borderRadius: 4,
  },
  labelInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    margin: '0 7px 0 0',
    borderRadius: 4,
  },
  labelInSearch: {
    height: 25,
    fontSize: 12,
    margin: '0 7px 0 0',
    borderRadius: 4,
  },
  labelInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
});

class StixCoreObjectLabels extends Component {
  render() {
    const { classes, labels, t, onClick, variant, theme, revoked } = this.props;
    let style = classes.label;
    if (variant === 'inList') {
      style = classes.labelInList;
    }
    if (variant === 'inSearch') {
      style = classes.labelInSearch;
    }
    return (
      <>
        {
          /* eslint-disable-next-line no-nested-ternary */
          !revoked && labels && labels.length > 0 ? (
            map(
              (label) => (
                <Tooltip key={label.id} title={label.value}>
                  <Chip
                    variant="outlined"
                    classes={{ root: style }}
                    label={truncate(label.value, 25)}
                    style={{
                      color: label.color,
                      borderColor: label.color,
                      backgroundColor: hexToRGB(label.color),
                      cursor: onClick ? 'pointer' : 'inherit',
                    }}
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      onClick?.('objectLabel', label.id, 'eq');
                    }}
                  />
                </Tooltip>
              ),
              take(3, labels),
            )
          ) : revoked ? (
            <Chip
              classes={{ root: style }}
              variant="outlined"
              label={t('Revoked')}
              style={{
                color: '#d32f2f',
                borderColor: '#d32f2f',
                backgroundColor: 'rgba(211, 47, 47, .1)',
              }}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                onClick?.('objectLabel', null, 'eq');
              }}
            />
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
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                onClick?.('objectLabel', null, 'eq');
              }}
            />
          )
        }
      </>
    );
  }
}

StixCoreObjectLabels.propTypes = {
  classes: PropTypes.object.isRequired,
  theme: PropTypes.object,
  t: PropTypes.func,
  variant: PropTypes.string,
  onClick: PropTypes.func,
  labels: PropTypes.array,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectLabels);
