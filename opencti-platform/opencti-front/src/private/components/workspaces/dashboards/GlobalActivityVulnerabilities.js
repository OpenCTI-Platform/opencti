import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipsHorizontalBars from '../../common/stix_core_relationships/StixCoreRelationshipsHorizontalBars';
import StixCoreRelationshipsDonut from '../../common/stix_core_relationships/StixCoreRelationshipsDonut';
import StixCoreRelationshipsAreaChart from '../../common/stix_core_relationships/StixCoreRelationshipsAreaChart';
import StixCoreRelationshipsVerticalBars from '../../common/stix_core_relationships/StixCoreRelationshipsVerticalBars';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class GlobalActivityVulnerabilities extends Component {
  render() {
    const {
      t, widget, startDate, endDate,
    } = this.props;
    switch (widget.visualizationType) {
      case 'horizontal-bar':
        return (
          <StixCoreRelationshipsHorizontalBars
            title={`${t('Activity')} - ${t('Vulnerabilities')}`}
            relationshipType="stix-core-relationship"
            toTypes={['Vulnerability']}
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute="created_at"
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <StixCoreRelationshipsDonut
            title={`${t('Activity')} - ${t('Vulnerability')}`}
            relationshipType="stix-core-relationship"
            toTypes={['Vulnerability']}
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute="created_at"
            variant="inLine"
          />
        );
      case 'area':
        return (
          <StixCoreRelationshipsAreaChart
            title={`${t('Activity')} - ${t('Intrusion Sets')}`}
            relationshipType="stix-core-relationship"
            toTypes={['Vulnerability']}
            startDate={startDate}
            endDate={endDate}
            dateAttribute="created_at"
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <StixCoreRelationshipsVerticalBars
            title={`${t('Activity')} - ${t('Vulnerabilities')}`}
            relationshipType="stix-core-relationship"
            toTypes={['Vulnerability']}
            startDate={startDate}
            endDate={endDate}
            dateAttribute="created_at"
            variant="inLine"
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

GlobalActivityVulnerabilities.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(GlobalActivityVulnerabilities);
