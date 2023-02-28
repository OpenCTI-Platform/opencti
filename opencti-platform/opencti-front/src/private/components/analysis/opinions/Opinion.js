import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ContainerHeader from '../../common/containers/ContainerHeader';
import OpinionDetails from './OpinionDetails';
import OpinionEdition from './OpinionEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import OpinionPopover from './OpinionPopover';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const OpinionComponent = ({ opinion }) => {
  const classes = useStyles();
  return (
      <div className={classes.container}>
        <ContainerHeader
          container={opinion}
          PopoverComponent={<OpinionPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <OpinionDetails opinion={opinion} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={opinion} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={12}>
            <ContainerStixObjectsOrStixRelationships
              container={opinion}
              isSupportParticipation={true}
            />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <StixCoreObjectExternalReferences stixCoreObjectId={opinion.id} />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory
              stixCoreObjectId={opinion.id}
              isSupportParticipation={true}
            />
          </Grid>
        </Grid>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <OpinionEdition opinionId={opinion.id} />
        </Security>
      </div>
  );
};

const Opinion = createFragmentContainer(OpinionComponent, {
  opinion: graphql`
    fragment Opinion_opinion on Opinion {
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
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      ...OpinionDetails_opinion
      ...ContainerHeader_container
      ...ContainerStixObjectsOrStixRelationships_container
    }
  `,
});

export default Opinion;
