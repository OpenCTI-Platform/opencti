import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityXOpenCTIIncidentsTableTime from '../events/x_opencti_incidents/EntityXOpenCTIIncidentsTableTime';
import EntityXOpenCTIIncidentsChart from '../events/x_opencti_incidents/EntityXOpenCTIIncidentsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class XOpenCTIIncidentsTimeseries extends Component {
  render() {
    const { configuration, handleOpenConfig } = this.props;
    switch (configuration.graph_type) {
      case 'table':
        return (
          <EntityXOpenCTIIncidentsTableTime
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
          />
        );
      case 'line':
        return (
          <EntityXOpenCTIIncidentsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
          />
        );
      default:
        return (
          <EntityXOpenCTIIncidentsChart
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

XOpenCTIIncidentsTimeseries.propTypes = {
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(XOpenCTIIncidentsTimeseries);
