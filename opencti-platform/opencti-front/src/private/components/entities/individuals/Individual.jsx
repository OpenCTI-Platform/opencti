import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import IndividualDetails from './IndividualDetails';
import IndividualEdition from './IndividualEdition';
import { KnowledgeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const styles = () => ({
  gridContainer: {
    marginBottom: 20,
  },
});

class IndividualComponent extends Component {
  render() {
    const { classes, individual, viewAs } = this.props;
    const lastReportsProps = viewAs === 'knowledge'
      ? { stixCoreObjectOrStixRelationshipId: individual.id }
      : { authorId: individual.id };
    return (
      <>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <IndividualDetails individual={individual} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview
              stixDomainObject={individual}
            />
          </Grid>
          {viewAs === 'knowledge' && (
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
              <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                stixObjectOrStixRelationshipId={individual.id}
                stixObjectOrStixRelationshipLink={`/dashboard/entities/individuals/${individual.id}/knowledge`}
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
            <StixCoreObjectExternalReferences
              stixCoreObjectId={individual.id}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectLatestHistory stixCoreObjectId={individual.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={individual.id}
          defaultMarkings={individual.objectMarking ?? []}
        />
        {!individual.isUser && (
          <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Individual'>
            <IndividualEdition individualId={individual.id} />
          </KnowledgeSecurity>
        )}
      </>
    );
  }
}

IndividualComponent.propTypes = {
  individual: PropTypes.object,
  classes: PropTypes.object,
  viewAs: PropTypes.string,
};

const Individual = createFragmentContainer(IndividualComponent, {
  individual: graphql`
    fragment Individual_individual on Individual {
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
      isUser
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
      ...IndividualDetails_individual
    }
  `,
});

export default withStyles(styles)(Individual);
