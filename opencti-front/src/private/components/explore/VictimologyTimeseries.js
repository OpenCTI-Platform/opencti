import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import inject18n from '../../../components/i18n';
import EntityStixRelationsChart from '../stix_relation/EntityStixRelationsChart';
import EntityStixRelationsTableTime from '../stix_relation/EntityStixRelationsTableTime';

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
          <EntityStixRelationsTableTime
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
            resolveInferences={true}
            resolveRelationType="attributed-to"
            resolveRelationRole="origin"
            resolveViaTypes={[
              {
                entityType: 'Organization',
                relationType: 'gathering',
                relationRole: 'part_of',
              },
            ]}
          />
        );
      case 'line':
        return (
          <EntityStixRelationsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            relationType="targets"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
            resolveRelationType="attributed-to"
            resolveRelationRole="origin"
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
          <EntityStixRelationsChart
            variant="explore"
            configuration={configuration}
            handleOpenConfig={handleOpenConfig.bind(this)}
            title={propOr('Widget', 'title', configuration)}
            entityId={pathOr(null, ['entity', 'id'], configuration)}
            relationType="targets"
            inferred={inferred}
            startDate={startDate}
            endDate={endDate}
            resolveRelationType="attributed-to"
            resolveRelationRole="origin"
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
