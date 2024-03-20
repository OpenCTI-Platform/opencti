import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import SystemDetails from './SystemDetails';
import SystemEdition from './SystemEdition';
import { KnowledgeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class SystemComponent extends Component {
  render() {
    const { classes, system, viewAs } = this.props;
    const lastReportsProps = viewAs === 'knowledge'
      ? { stixCoreObjectOrStixRelationshipId: system.id }
      : { authorId: system.id };
    return (
      <>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <SystemDetails system={system} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview
              stixDomainObject={system}
            />
          </Grid>
          {viewAs === 'knowledge' && (
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
              <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                stixObjectOrStixRelationshipId={system.id}
                stixObjectOrStixRelationshipLink={`/dashboard/entities/systems/${system.id}/knowledge`}
              />
            </Grid>
          )}
          <Grid
            item={true}
            xs={viewAs === 'knowledge' ? 6 : 12}
            style={{ marginTop: 30 }}
          >
            <StixCoreObjectOrStixRelationshipLastContainers
              {...lastReportsProps}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectExternalReferences stixCoreObjectId={system.id} />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectLatestHistory stixCoreObjectId={system.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={system.id}
          defaultMarkings={system.objectMarking ?? []}
        />
        <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='System'>
          <SystemEdition systemId={system.id} />
        </KnowledgeSecurity>
      </>
    );
  }
}

SystemComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  viewAs: PropTypes.string,
};

const System = createFragmentContainer(SystemComponent, {
  system: graphql`
    fragment System_system on System {
      id
      standard_id
      entity_type
      x_opencti_stix_ids
      spec_version
      revoked
      x_opencti_reliability
      confidence
      created
      modified
      created_at
      updated_at
      createdBy {
        ... on Identity {
          id
          name
          entity_type
          x_opencti_reliability
        }
      }
      creators {
        id
        name
      }
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      objectLabel {
        id
        value
        color
      }
      name
      x_opencti_aliases
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      ...SystemDetails_system
    }
  `,
});

export default withStyles(styles)(System);
