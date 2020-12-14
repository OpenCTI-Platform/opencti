import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixCoreRelationshipsPie from '../common/stix_core_relationships/EntityStixCoreRelationshipsPie';
import EntityStixCoreRelationshipsRadar from '../common/stix_core_relationships/StixCoreObjectStixCoreRelationshipsCloud';
import EntityStixCoreRelationshipsDonut from '../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';
import EntityStixCoreRelationshipsTable from '../common/stix_core_relationships/EntityStixCoreRelationshipsTable';

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
          <EntityStixCoreRelationshipsTable
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType={propOr('Sector', 'entity_type', configuration)}
            relationshipType="targets"
            field="name"
            startDate={startDate}
            endDate={endDate}
          />
        );
      case 'radar':
        return (
          <EntityStixCoreRelationshipsRadar
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType={propOr('Sector', 'entity_type', configuration)}
            relationshipType="targets"
            field="name"
            startDate={startDate}
            endDate={endDate}
          />
        );
      case 'donut':
        return (
          <EntityStixCoreRelationshipsDonut
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType={propOr('Sector', 'entity_type', configuration)}
            relationshipType="targets"
            field="name"
            startDate={startDate}
            endDate={endDate}
          />
        );
      default:
        return (
          <EntityStixCoreRelationshipsPie
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
