import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import StixCoreObjectReportsHorizontalBars from '../../analysis/reports/StixCoreObjectReportsHorizontalBars';
import StixCoreObjectReportsAreaChart from '../../analysis/reports/StixCoreObjectReportsAreaChart';
import StixCoreObjectReportsVerticalBars from '../../analysis/reports/StixCoreObjectReportsVerticalBars';
import StixCoreObjectReportsDonut from '../../analysis/reports/StixCoreObjectReportsDonut';
import StixDomainObjectsList from '../../common/stix_domain_objects/StixDomainObjectsList';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class ThreatVictimologyAll extends Component {
  render() {
    const { t, widget, startDate, endDate, timeField } = this.props;
    let dateAttribute = 'created_at';
    if (timeField === 'functional') {
      dateAttribute = 'created';
    }
    switch (widget.visualizationType) {
      case 'horizontal-bar':
        return (
          <StixCoreObjectReportsHorizontalBars
            title={`${t('Reports')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            field="created-by.internal_id"
            startDate={startDate}
            endDate={endDate}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <StixCoreObjectReportsDonut
            title={`${t('Reports')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            field="created-by.internal_id"
            startDate={startDate}
            endDate={endDate}
            variant="inLine"
          />
        );
      case 'area':
        return (
          <StixCoreObjectReportsAreaChart
            title={`${t('Reports')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            field="created-by.internal_id"
            startDate={startDate}
            endDate={endDate}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <StixCoreObjectReportsVerticalBars
            title={`${t('Reports')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            startDate={startDate}
            endDate={endDate}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <StixDomainObjectsList
            title={`${t('Reports')} - ${widget.entity.name}`}
            types={['Report']}
            dateAttribute={dateAttribute}
            variant="inLine"
            containerId={widget.entity.id}
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

ThreatVictimologyAll.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(inject18n, withStyles(styles))(ThreatVictimologyAll);
