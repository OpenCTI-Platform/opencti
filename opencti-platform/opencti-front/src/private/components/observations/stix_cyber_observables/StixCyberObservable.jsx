import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import StixCyberObservableDetails from './StixCyberObservableDetails';
import StixCyberObservableEdition from './StixCyberObservableEdition';
import { KnowledgeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCyberObservableOverview from './StixCyberObservableOverview';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const styles = () => ({
  gridContainer: {
    marginBottom: 20,
  },
});

class StixCyberObservableComponent extends Component {
  render() {
    const { classes, stixCyberObservable } = this.props;
    return (
      <>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixCyberObservableDetails
              stixCyberObservable={stixCyberObservable}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixCyberObservableOverview
              stixCyberObservable={stixCyberObservable}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={stixCyberObservable.id}
              stixObjectOrStixRelationshipLink={`/dashboard/observations/observables/${stixCyberObservable.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectOrStixRelationshipLastContainers
              stixCoreObjectOrStixRelationshipId={stixCyberObservable.id}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectExternalReferences
              stixCoreObjectId={stixCyberObservable.id}
            />
          </Grid>
          <Grid item={true} xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectLatestHistory
              stixCoreObjectId={stixCyberObservable.id}
            />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={stixCyberObservable.id}
          defaultMarkings={stixCyberObservable.objectMarking ?? []}
        />
        <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Stix-Cyber-Observable'>
          <StixCyberObservableEdition
            stixCyberObservableId={stixCyberObservable.id}
          />
        </KnowledgeSecurity>
      </>
    );
  }
}

StixCyberObservableComponent.propTypes = {
  stixCyberObservable: PropTypes.object,
  classes: PropTypes.object,
};

const StixCyberObservable = createFragmentContainer(
  StixCyberObservableComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservable_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        standard_id
        x_opencti_stix_ids
        spec_version
        created_at
        updated_at
        createdBy {
          ... on Identity {
            id
            name
            entity_type
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
        observable_value
        x_opencti_score
        ...StixCyberObservableDetails_stixCyberObservable
        ...StixCyberObservableHeader_stixCyberObservable
      }
    `,
  },
);

export default withStyles(styles)(StixCyberObservable);
