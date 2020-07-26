import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  compose, map, take, sortWith, prop, ascend, pipe,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import Slide from '@material-ui/core/Slide';
import inject18n from '../../../../components/i18n';

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
  hexToRGB(hex, transp = 0.1) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgb(${r}, ${g}, ${b}, ${transp})`;
  }

  render() {
    const {
      classes, labels, t, onClick, variant,
    } = this.props;
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
      <div className={classes.labels}>
        {labelsNodes.length > 0 ? (
          map(
            (label) => (
              <Chip
                key={label.id}
                variant="outlined"
                classes={{ root: style }}
                label={label.value}
                style={{
                  color: label.color,
                  borderColor: label.color,
                  backgroundColor: this.hexToRGB(label.color),
                }}
                onClick={
                  typeof onClick === 'function'
                    ? onClick.bind(this, 'labels', label.id, label.value)
                    : null
                }
              />
            ),
            take(3, labelsNodes),
          )
        ) : (
          <Chip
            classes={{ root: style }}
            variant="outlined"
            label={t('No label')}
            style={{
              color: '#ffffff',
              borderColor: '#ffffff',
              backgroundColor: this.hexToRGB('#ffffff'),
            }}
            onClick={
              typeof onClick === 'function'
                ? onClick.bind(this, 'labels', null, null)
                : null
            }
          />
        )}
      </div>
    );
  }
}

StixCoreObjectLabels.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  variant: PropTypes.string,
  onClick: PropTypes.func,
  labels: PropTypes.object,
};

export default compose(inject18n, withStyles(styles))(StixCoreObjectLabels);
