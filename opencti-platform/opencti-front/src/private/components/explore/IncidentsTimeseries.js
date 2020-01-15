import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityIncidentsTableTime from '../threats/incidents/EntityIncidentsTableTime';
import EntityIncidentsChart from '../threats/incidents/EntityIncidentsChart';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class IncidentsTimeseries extends Component {
  render() {
    const { configuration, handleOpenConfig } = this.props;
    switch (configuration.graph_type) {
      case 'table':
        return (
          <EntityIncidentsTableTime
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
          />
        );
      case 'line':
        return (
          <EntityIncidentsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
          />
        );
      default:
        return (
          <EntityIncidentsChart
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

IncidentsTimeseries.propTypes = {
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
)(IncidentsTimeseries);
