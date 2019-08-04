import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixRelationsPie from '../common/stix_relations/EntityStixRelationsPie';
import EntityStixRelationsRadar from '../common/stix_relations/EntityStixRelationsRadar';
import EntityStixRelationsDonut from '../common/stix_relations/EntityStixRelationsDonut';
import EntityStixRelationsTable from '../common/stix_relations/EntityStixRelationsTable';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class VictimologyDistribution extends Component {
  render() {
    const {
      configuration,
      handleOpenConfig,
      inferred,
      startDate,
      endDate,
    } = this.props;
    switch (configuration.graph_type) {
      case 'table':
        return (
          <EntityStixRelationsTable
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType={propOr('Sector', 'entity_type', configuration)}
            relationType="targets"
            field="name"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
            resolveInferences={inferred}
            resolveRelationType={
              pathOr(null, ['entity', 'type'], configuration) === 'malware'
                ? 'uses'
                : 'attributed-to'
            }
            resolveRelationRole={
              pathOr(null, ['entity', 'type'], configuration) === 'malware'
                ? 'usage'
                : 'origin'
            }
            resolveViaTypes={[
              {
                entityType: 'Organization',
                relationType: 'gathering',
                relationRole: 'part_of',
              },
            ]}
          />
        );
      case 'radar':
        return (
          <EntityStixRelationsRadar
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType={propOr('Sector', 'entity_type', configuration)}
            relationType="targets"
            field="name"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
            resolveInferences={inferred}
            resolveRelationType={
              pathOr(null, ['entity', 'type'], configuration) === 'malware'
                ? 'uses'
                : 'attributed-to'
            }
            resolveRelationRole={
              pathOr(null, ['entity', 'type'], configuration) === 'malware'
                ? 'usage'
                : 'origin'
            }
            resolveViaTypes={[
              {
                entityType: 'Organization',
                relationType: 'gathering',
                relationRole: 'part_of',
              },
            ]}
          />
        );
      case 'donut':
        return (
          <EntityStixRelationsDonut
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType={propOr('Sector', 'entity_type', configuration)}
            relationType="targets"
            field="name"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
            resolveInferences={inferred}
            resolveRelationType={
              pathOr(null, ['entity', 'type'], configuration) === 'malware'
                ? 'uses'
                : 'attributed-to'
            }
            resolveRelationRole={
              pathOr(null, ['entity', 'type'], configuration) === 'malware'
                ? 'usage'
                : 'origin'
            }
            resolveViaTypes={[
              {
                entityType: 'Organization',
                relationType: 'gathering',
                relationRole: 'part_of',
              },
            ]}
          />
        );
      default:
        return (
          <EntityStixRelationsPie
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            entityType={propOr('Sector', 'entity_type', configuration)}
            relationType="targets"
            field="name"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
            resolveInferences={inferred}
            resolveRelationType={
              pathOr(null, ['entity', 'type'], configuration) === 'malware'
                ? 'uses'
                : 'attributed-to'
            }
            resolveRelationRole={
              pathOr(null, ['entity', 'type'], configuration) === 'malware'
                ? 'usage'
                : 'origin'
            }
            resolveViaTypes={[
              {
                entityType: 'Organization',
                relationType: 'gathering',
                relationRole: 'part_of',
              },
            ]}
          />
        );
    }
  }
}

VictimologyDistribution.propTypes = {
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
)(VictimologyDistribution);
