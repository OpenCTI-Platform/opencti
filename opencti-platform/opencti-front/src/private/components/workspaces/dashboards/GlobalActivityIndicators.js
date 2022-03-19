import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import IndicatorsHorizontalBars from '../../observations/indicators/IndicatorsHorizontalBars';
import IndicatorsDonut from '../../observations/indicators/IndicatorsDonut';
import IndicatorsVerticalBars from '../../observations/indicators/IndicatorsVerticalBars';
import IndicatorsAreaChart from '../../observations/indicators/IndicatorsAreaChart';
import IndicatorsList from '../../observations/indicators/IndicatorsList';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class GlobalActivityIndicators extends Component {
  render() {
    const { t, widget, startDate, endDate, field, timeField } = this.props;
    let dateAttribute = 'created_at';
    if (timeField === 'functional') {
      dateAttribute = 'valid_from';
    }
    switch (widget.visualizationType) {
      case 'horizontal-bar':
        return (
          <IndicatorsHorizontalBars
            title={`${t('Activity')} - ${t('Indicators')} (${
              field || 'pattern_type'
            })`}
            field={field || 'pattern_type'}
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <IndicatorsDonut
            title={`${t('Activity')} - ${t('Indicators')} (${
              field || 'pattern_type'
            })`}
            field={field || 'pattern_type'}
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'area':
        return (
          <IndicatorsAreaChart
            title={`${t('Activity')} - ${t('Indicators')}`}
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <IndicatorsVerticalBars
            title={`${t('Activity')} - ${t('Indicators')}`}
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <IndicatorsList
            title={`${t('Activity')} - ${t('Indicators')} (${
              field || 'pattern_type'
            })`}
            field={field || 'pattern_type'}
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

GlobalActivityIndicators.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  timeField: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  field: PropTypes.string,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(GlobalActivityIndicators);
