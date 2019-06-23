import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityCampaignsChart from '../campaign/EntityCampaignsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class CampaignsTimeseries extends Component {
  render() {
    const { configuration, onUpdate, onDelete } = this.props;
    switch (configuration.graph_type) {
      case 'chart':
        return (
            <EntityCampaignsChart
              variant="explore"
              configuration={configuration}
              onUpdate={onUpdate.bind(this)}
              onDelete={onDelete.bind(this)}
              title={propOr('Widget', 'title', configuration)}
              entityId={pathOr(null, ['entity', 'id'], configuration)}
            />
        );
      default:
        return (
            <EntityCampaignsChart
              variant="explore"
              configuration={configuration}
              onUpdate={onUpdate.bind(this)}
              onDelete={onDelete.bind(this)}
              title={propOr('Widget', 'title', configuration)}
              entityId={pathOr(null, ['entity', 'id'], configuration)}
            />
        );
    }
  }
}

CampaignsTimeseries.propTypes = {
  configuration: PropTypes.object,
  onUpdate: PropTypes.func,
  onDelete: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(CampaignsTimeseries);
