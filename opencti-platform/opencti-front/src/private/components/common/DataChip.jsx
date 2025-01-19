import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, take } from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import inject18n from '../../../components/i18n';
import { hexToRGB } from '../../../utils/Colors';
import { truncate } from '../../../utils/String';

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

class DataChips extends Component {
  render() {
    const { attribute, classes, elements, onClick, theme } = this.props;
    const style = classes.labelInList;
    const defaultColor = theme.palette.mode === 'dark' ? '#ffffff' : '#000000';
    return (
      <>
        {
          /* eslint-disable-next-line no-nested-ternary */
          elements && elements.length > 0 ? (
            map(
              (element) => (
                <Tooltip key={element.id} title={element.value}>
                  <Chip
                    variant="outlined"
                    classes={{ root: style }}
                    label={truncate(element.value, 25)}
                    style={{
                      color: element.color,
                      borderColor: element.color,
                      backgroundColor: hexToRGB(element.color ?? defaultColor),
                      cursor: onClick ? 'pointer' : 'inherit',
                    }}
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      if (element.id && onClick) {
                        onClick(attribute, element.id, 'eq');
                      }
                    }}
                  />
                </Tooltip>
              ),
              take(3, elements),
            )
          ) : (
            <Chip
              classes={{ root: style }}
              variant="outlined"
              label={'-'}
              style={{ backgroundColor: hexToRGB(defaultColor) }}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                onClick?.(attribute, null, 'eq');
              }}
            />
          )
        }
      </>
    );
  }
}

DataChips.propTypes = {
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
)(DataChips);
