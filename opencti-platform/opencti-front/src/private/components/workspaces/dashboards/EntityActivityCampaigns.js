import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import StixCoreObjectCampaignsVerticalBars from '../../threats/campaigns/StixCoreObjectCampaignsVerticalBars';
import StixCoreObjectCampaignsAreaChart from '../../threats/campaigns/StixCoreObjectCampaignsAreaChart';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class EntityActivityCampaigns extends Component {
  render() {
    const { t, widget, startDate, endDate, timeField } = this.props;
    let dateAttribute = 'created_at';
    if (timeField === 'functional') {
      dateAttribute = 'first_seen';
    }
    switch (widget.visualizationType) {
      case 'area':
        return (
          <StixCoreObjectCampaignsAreaChart
            title={`${t('Campaigns')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <StixCoreObjectCampaignsVerticalBars
            title={`${t('Campaigns')} - ${widget.entity.name}`}
            stixCoreObjectId={widget.entity.id}
            startDate={startDate}
            endDate={endDate}
            dateAttribute={dateAttribute}
            variant="inLine"
          />
        );
      case 'donut':
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

EntityActivityCampaigns.propTypes = {
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  timeField: PropTypes.string,
  widget: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(EntityActivityCampaigns);
