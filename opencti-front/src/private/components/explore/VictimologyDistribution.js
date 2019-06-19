import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import EntityStixRelationsPie from '../stix_relation/EntityStixRelationsPie';
import EntityStixRelationsRadar from '../stix_relation/EntityStixRelationsRadar';
import EntityStixRelationsDonut from '../stix_relation/EntityStixRelationsDonut';
import EntityStixRelationsTable from '../stix_relation/EntityStixRelationsTable';

const styles = () => ({
  container: {
    margin: 0,
  },
});

class VictimologyDistribution extends Component {
  render() {
    const { configuration, onUpdate, onDelete } = this.props;
    switch (configuration.graph_type) {
      case 'table':
        return (
          <Grid item={true} xs={Number(propOr(4, 'size', configuration))} style={{ marginBottom: 30 }}>
            <EntityStixRelationsTable
              variant="explore"
              configuration={configuration}
              onUpdate={onUpdate.bind(this)}
              onDelete={onDelete.bind(this)}
              title={propOr('Widget', 'title', configuration)}
              entityId={pathOr(null, ['entity', 'id'], configuration)}
              entityType={propOr('Sector', 'entity_type', configuration)}
              relationType="targets"
              field="name"
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
          </Grid>
        );
      case 'radar':
        return (
          <Grid item={true} xs={Number(propOr(4, 'size', configuration))} style={{ marginBottom: 30 }}>
            <EntityStixRelationsRadar
              variant="explore"
              configuration={configuration}
              onUpdate={onUpdate.bind(this)}
              onDelete={onDelete.bind(this)}
              title={propOr('Widget', 'title', configuration)}
              entityId={pathOr(null, ['entity', 'id'], configuration)}
              entityType={propOr('Sector', 'entity_type', configuration)}
              relationType="targets"
              field="name"
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
          </Grid>
        );
      case 'donut':
        return (
          <Grid item={true} xs={Number(propOr(4, 'size', configuration))} style={{ marginBottom: 30 }}>
            <EntityStixRelationsDonut
              variant="explore"
              configuration={configuration}
              onUpdate={onUpdate.bind(this)}
              onDelete={onDelete.bind(this)}
              title={propOr('Widget', 'title', configuration)}
              entityId={pathOr(null, ['entity', 'id'], configuration)}
              entityType={propOr('Sector', 'entity_type', configuration)}
              relationType="targets"
              field="name"
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
          </Grid>
        );
      default:
        return (
          <Grid item={true} xs={Number(propOr(4, 'size', configuration))} style={{ marginBottom: 30 }}>
            <EntityStixRelationsPie
              variant="explore"
              configuration={configuration}
              onUpdate={onUpdate.bind(this)}
              onDelete={onDelete.bind(this)}
              title={propOr('Widget', 'title', configuration)}
              entityId={pathOr(null, ['entity', 'id'], configuration)}
              entityType={propOr('Sector', 'entity_type', configuration)}
              relationType="targets"
              field="name"
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
          </Grid>
        );
    }
  }
}

VictimologyDistribution.propTypes = {
  configuration: PropTypes.object,
  onUpdate: PropTypes.func,
  onDelete: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(VictimologyDistribution);
