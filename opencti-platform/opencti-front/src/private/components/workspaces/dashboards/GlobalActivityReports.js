import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import ReportsHorizontalBars from '../../analysis/reports/ReportsHorizontalBars';
import ReportsAreaChart from '../../analysis/reports/ReportsAreaChart';
import ReportsVerticalBars from '../../analysis/reports/ReportsVerticalBars';
import ReportsDonut from '../../analysis/reports/ReportsDonut';
import StixDomainObjectsTimeline from '../../common/stix_domain_objects/StixDomainObjectsTimeline';
import StixDomainObjectsList from '../../common/stix_domain_objects/StixDomainObjectsList';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class GlobalActivityReports extends Component {
  render() {
    const { t, widget, startDate, endDate, timeField, onConfigChange } = this.props;
    let dateAttribute = 'created_at';
    if (timeField === 'functional') {
      dateAttribute = 'created';
    }
    switch (widget.visualizationType) {
      case 'horizontal-bar':
        return (
          <ReportsHorizontalBars
            title={`${t('Activity')} - ${t('Reports')}`}
            field="created-by.internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <ReportsDonut
            title={`${t('Activity')} - ${t('Reports')}`}
            field="created-by.internal_id"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <ReportsVerticalBars
            title={`${t('Activity')} - ${t('Reports')}`}
            startDate={startDate}
            endDate={endDate}
            field={dateAttribute}
            variant="inLine"
          />
        );
      case 'area':
        return (
          <ReportsAreaChart
            title={`${t('Activity')} - ${t('Reports')}`}
            startDate={startDate}
            endDate={endDate}
            field={dateAttribute}
            variant="inLine"
          />
        );
      case 'timeline':
        return (
          <StixDomainObjectsTimeline
            title={`${t('Activity')} - ${t('Reports')}`}
            types={['Report']}
            field={dateAttribute}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <StixDomainObjectsList
            title={`${t('Activity')} - ${t('Reports')}`}
            types={['Report']}
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

GlobalActivityReports.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  timeField: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  onConfigChange: PropTypes.func,
};

export default R.compose(inject18n, withStyles(styles))(GlobalActivityReports);
