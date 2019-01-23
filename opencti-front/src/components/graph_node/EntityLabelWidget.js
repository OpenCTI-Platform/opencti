import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import inject18n from '../i18n';

class EntityLabelWidget extends Component {
  render() {
    return <div style={{
      padding: '5px 8px 5px 8px',
      backgroundColor: '#14262c',
      color: '#ffffff',
      fontSize: 12,
    }}>{this.props.t(`relation_${this.props.model.label}`)}</div>;
  }
}

EntityLabelWidget.propTypes = {
  model: PropTypes.object,
  t: PropTypes.func,
};

export default inject18n(EntityLabelWidget);
