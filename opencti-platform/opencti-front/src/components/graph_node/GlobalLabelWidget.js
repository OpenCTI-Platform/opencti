import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../i18n';

const styles = () => ({
  item: {
    textAlign: 'center',
    padding: '5px 8px 5px 8px',
    backgroundColor: '#14262c',
    color: '#ffffff',
    fontSize: 12,
    position: 'relative',
    zIndex: 1500,
  },
});

class GlobalLabelWidget extends Component {
  render() {
    const {
      classes,
      model: { label },
    } = this.props;
    return (
      <div className={classes.item}>
        <strong>{label}</strong>
      </div>
    );
  }
}

GlobalLabelWidget.propTypes = {
  model: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(GlobalLabelWidget);
