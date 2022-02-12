import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import StixCoreObjectIndicatorsHorizontalBars from '../../observations/indicators/StixCoreObjectIndicatorsHorizontalBars';
import StixCoreObjectIndicatorsDonut from '../../observations/indicators/StixCoreObjectIndicatorsDonut';
import StixCoreObjectIndicatorsAreaChart from '../../observations/indicators/StixCoreObjectIndicatorsAreaChart';
import StixCoreObjectIndicatorsVerticalBars from '../../observations/indicators/StixCoreObjectIndicatorsVerticalBars';

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
          <StixCoreObjectIndicatorsHorizontalBars
            title={`${t('Indicators')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            field="pattern_type"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <StixCoreObjectIndicatorsDonut
            title={`${t('Indicators')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            field="pattern_type"
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'area':
        return (
          <StixCoreObjectIndicatorsAreaChart
            title={`${t('Indicators')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <StixCoreObjectIndicatorsVerticalBars
            title={`${t('Indicators')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
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

ThreatVictimologyAll.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  timeField: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(inject18n, withStyles(styles))(ThreatVictimologyAll);
