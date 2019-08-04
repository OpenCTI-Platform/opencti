import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityCampaignsTableTime from '../threats/campaigns/EntityCampaignsTableTime';
import EntityCampaignsChart from '../threats/campaigns/EntityCampaignsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class CampaignsTimeseries extends Component {
  render() {
    const { configuration, handleOpenConfig } = this.props;
    switch (configuration.graph_type) {
      case 'table':
        return (
          <EntityCampaignsTableTime
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
          />
        );
      case 'line':
        return (
          <EntityCampaignsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
          />
        );
      default:
        return (
          <EntityCampaignsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
          />
        );
    }
  }
}

CampaignsTimeseries.propTypes = {
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  inferred: PropTypes.bool,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(CampaignsTimeseries);
