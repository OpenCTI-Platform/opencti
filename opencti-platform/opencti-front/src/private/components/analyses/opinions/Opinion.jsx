import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ContainerHeader from '../../common/containers/ContainerHeader';
import OpinionDetails from './OpinionDetails';
import OpinionEdition from './OpinionEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import OpinionPopover from './OpinionPopover';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const OpinionComponent = ({ opinion, enableReferences }) => {
  const classes = useStyles();
  return (
    <>
      <CollaborativeSecurity
        data={opinion}
        needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
        placeholder={
          <ContainerHeader
            container={opinion}
            PopoverComponent={<OpinionPopover opinion={opinion} />}
          />
        }
      >
        <ContainerHeader
          container={opinion}
          PopoverComponent={<OpinionPopover opinion={opinion} />}
          popoverSecurity={[KNOWLEDGE_KNPARTICIPATE]}
        />
      </CollaborativeSecurity>
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
        <Grid item={true} xs={12} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            container={opinion}
            isSupportParticipation={true}
            enableReferences={enableReferences}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences stixCoreObjectId={opinion.id} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory
            stixCoreObjectId={opinion.id}
            isSupportParticipation={true}
          />
        </Grid>
      </Grid>
      <CollaborativeSecurity data={opinion} needs={[KNOWLEDGE_KNUPDATE]}>
        <OpinionEdition opinionId={opinion.id} />
      </CollaborativeSecurity>
    </>
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
        id
        name
        entity_type
        x_opencti_reliability
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
