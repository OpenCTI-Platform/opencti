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
    pointerEvents: 'auto',
    fontSize: 12,
    '&:hover': {
      background: '#1e3f49',
    },
  },
});

class EntityLabelWidget extends Component {
  render() {
    return <div className={this.props.classes.item} onClick={this.props.model.setSelected.bind(this, true)}>
      <strong>{this.props.t(`relation_${this.props.model.label}`)}</strong>
      <br />
      {this.props.model.firstSeen ? this.props.nsd(this.props.model.firstSeen) : ''}
      <br />
      {this.props.model.lastSeen ? this.props.nsd(this.props.model.lastSeen) : ''}
    </div>;
  }
}

EntityLabelWidget.propTypes = {
  model: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityLabelWidget);
