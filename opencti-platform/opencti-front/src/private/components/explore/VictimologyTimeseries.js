import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixCoreRelationshipsChart from '../common/stix_core_relationships/EntityStixCoreRelationshipsChart';
import EntityStixCoreRelationshipsTableTime from '../common/stix_core_relationships/EntityStixCoreRelationshipsTableTime';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class VictimologyDistribution extends Component {
  render() {
    const {
      configuration, handleOpenConfig, startDate, endDate,
    } = this.props;
    switch (configuration.graph_type) {
      case 'table':
        return (
          <EntityStixCoreRelationshipsTableTime
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            relationshipType="targets"
            field="name"
            startDate={startDate}
            endDate={endDate}
          />
        );
      case 'line':
        return (
          <EntityStixCoreRelationshipsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            relationshipType="targets"
            startDate={startDate}
            endDate={endDate}
          />
        );
      default:
        return (
          <EntityStixCoreRelationshipsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            relationshipType="targets"
            startDate={startDate}
            endDate={endDate}
          />
        );
    }
  }
}

VictimologyDistribution.propTypes = {
  configuration: PropTypes.object,
  handleOpenConfig: PropTypes.func,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(VictimologyDistribution);
