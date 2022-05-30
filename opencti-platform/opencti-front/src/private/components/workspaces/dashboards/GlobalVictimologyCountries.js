import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import GlobalVictimologyMap from '../../common/location/GlobalVictimologyMap';
import StixCoreRelationshipsHorizontalBars from '../../common/stix_core_relationships/StixCoreRelationshipsHorizontalBars';
import StixCoreRelationshipsDonut from '../../common/stix_core_relationships/StixCoreRelationshipsDonut';
import StixCoreRelationshipsAreaChart from '../../common/stix_core_relationships/StixCoreRelationshipsAreaChart';
import StixCoreRelationshipsVerticalBars from '../../common/stix_core_relationships/StixCoreRelationshipsVerticalBars';
import StixCoreRelationshipsDistributionList from '../../common/stix_core_relationships/StixCoreRelationshipsDistributionList';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class GlobalVictimologyCountries extends Component {
  render() {
    const { t, startDate, endDate, widget, mapReload, timeField } = this.props;
    let dateAttribute = 'created_at';
    if (timeField === 'functional') {
      dateAttribute = 'start_time';
    }
    switch (widget.visualizationType) {
      case 'map':
        if (mapReload) return <div />;
        return (
          <GlobalVictimologyMap
            title={`${t('Victimology')} - ${t('Countries')}`}
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'horizontal-bar':
        return (
          <StixCoreRelationshipsHorizontalBars
            title={`${t('Victimology')} - ${t('Countries')}`}
            toTypes={['Country']}
            relationshipType="targets"
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <StixCoreRelationshipsDonut
            title={`${t('Victimology')} - ${t('Countries')}`}
            toTypes={['Country']}
            relationshipType="targets"
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'area':
        return (
          <StixCoreRelationshipsAreaChart
            title={`${t('Victimology')} - ${t('Countries')}`}
            toTypes={['Country']}
            relationshipType="targets"
            startDate={startDate}
            endDate={endDate}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <StixCoreRelationshipsVerticalBars
            title={`${t('Victimology')} - ${t('Countries')}`}
            toTypes={['Country']}
            relationshipType="targets"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <StixCoreRelationshipsDistributionList
            title={`${t('Victimology')} - ${t('Countries')}`}
            toTypes={['Country']}
            relationshipType="targets"
            field="internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
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

GlobalVictimologyCountries.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  timeField: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  mapReload: PropTypes.bool,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(GlobalVictimologyCountries);
