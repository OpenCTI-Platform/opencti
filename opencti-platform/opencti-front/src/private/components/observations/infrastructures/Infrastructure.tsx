import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import InfrastructureDetails from './InfrastructureDetails';
import InfrastructureEdition from './InfrastructureEdition';
import InfrastructurePopover from './InfrastructurePopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import { Infrastructure_infrastructure$key } from './__generated__/Infrastructure_infrastructure.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const InfrastructureFragment = graphql`
  fragment Infrastructure_infrastructure on Infrastructure {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    spec_version
    revoked
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
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
    name
    aliases
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...InfrastructureDetails_infrastructure
  }
`;

const Infrastructure = ({ data }: { data: Infrastructure_infrastructure$key }) => {
  const classes = useStyles();
  const infrastructure = useFragment(InfrastructureFragment, data);
  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Infrastructure'}
        stixDomainObject={infrastructure}
        PopoverComponent={<InfrastructurePopover />}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <InfrastructureDetails infrastructure={infrastructure} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={infrastructure} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={infrastructure.id}
            stixObjectOrStixRelationshipLink={`/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={infrastructure.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={infrastructure.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={infrastructure.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={infrastructure.id}
        defaultMarkings={(infrastructure.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <InfrastructureEdition infrastructureId={infrastructure.id} />
      </Security>
    </div>
  );
};

export default Infrastructure;
