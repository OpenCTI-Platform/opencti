import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipsList from '../../common/stix_core_relationships/StixCoreRelationshipsList';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class GlobalActivityStixCoreRelationships extends Component {
  render() {
    const { t, widget, startDate, endDate, timeField, onConfigChange } = this.props;
    let dateAttribute = 'created_at';
    if (timeField === 'functional') {
      dateAttribute = 'created';
    }
    switch (widget.visualizationType) {
      case 'list':
        return (
          <StixCoreRelationshipsList
            title={`${t('Activity')} - ${t('Relationships')}`}
            dateAttribute={dateAttribute}
            variant="inLine"
            config={widget.config}
            onConfigChange={onConfigChange.bind(this)}
            startDate={startDate}
            endDate={endDate}
          />
        );
      default:
        return (
          <div style={{ display: 'table', height: '100%', width: '100%' }}>
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t('Not implemented yet.')}
            </span>
          </div>
        );
    }
  }
}

GlobalActivityStixCoreRelationships.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  timeField: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  onConfigChange: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(GlobalActivityStixCoreRelationships);
