import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, take, sortWith, prop, ascend, pipe } from 'ramda';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';
import Slide from '@mui/material/Slide';
import Tooltip from '@mui/material/Tooltip';
import inject18n from '../../../../components/i18n';
import { hexToRGB } from '../../../../utils/Colors';
import { truncate } from '../../../../utils/String';

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
    marginRight: 7,
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
    const labelsNodes = pipe(
      map((n) => n.node),
      sortWith([ascend(prop('value'))]),
    )(labels.edges);
    return (
      <div className={classes.objectLabel}>
        {
          /* eslint-disable-next-line no-nested-ternary */
          !revoked && labelsNodes.length > 0 ? (
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
                    }}
                    onClick={
                      typeof onClick === 'function'
                        ? onClick.bind(
                          this,
                          'labelledBy',
                          label.id,
                          label.value,
                        )
                        : null
                    }
                  />
                </Tooltip>
              ),
              take(3, labelsNodes),
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
              onClick={
                typeof onClick === 'function'
                  ? onClick.bind(this, 'labelledBy', null, null)
                  : null
              }
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
              onClick={
                typeof onClick === 'function'
                  ? onClick.bind(this, 'labelledBy', null, null)
                  : null
              }
            />
          )
        }
      </div>
    );
  }
}

StixCoreObjectLabels.propTypes = {
  classes: PropTypes.object.isRequired,
  theme: PropTypes.object,
  t: PropTypes.func,
  variant: PropTypes.string,
  onClick: PropTypes.func,
  labels: PropTypes.object,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixCoreObjectLabels);
