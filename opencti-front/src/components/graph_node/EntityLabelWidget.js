import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, head } from 'ramda';
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
  itemInferred: {
    textAlign: 'center',
    padding: '5px 8px 5px 8px',
    backgroundColor: '#14262c',
    color: '#ffffff',
    pointerEvents: 'auto',
    fontSize: 12,
  },
});

class EntityLabelWidget extends Component {
  render() {
    const {
      t, nsd, classes, model, model: { extras },
    } = this.props;
    if (extras.length === 1) {
      const label = head(extras);
      if (label.inferred === true) {
        return (
          <div className={classes.itemInferred}>
            <strong>{t(`relation_${label.relationship_type}`)}</strong>
            <br />
            <em>{t('Inferred')}</em>
          </div>
        );
      }
      return (
        <div className={classes.item} onClick={model.setSelected.bind(this, true)}>
          <strong>{t(`relation_${label.relationship_type}`)}</strong>
          <br/>
          {nsd(label.first_seen)}
          <br/>
          {nsd(label.last_seen)}
        </div>
      );
    }
    return (
        <div className={classes.itemInferred}>
          <strong>{extras.length} {t('relations')}</strong>
        </div>
    );
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
