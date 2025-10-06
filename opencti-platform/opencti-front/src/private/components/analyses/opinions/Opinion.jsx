import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Grid } from '@components';
import ContainerHeader from '../../common/containers/ContainerHeader';
import OpinionDetails from './OpinionDetails';
import OpinionEdition from './OpinionEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import { CollaborativeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';

const OpinionComponent = ({ opinion, enableReferences }) => {
  return (
    <>
      <CollaborativeSecurity
        data={opinion}
        needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}
        placeholder={
          <ContainerHeader
            container={opinion}
            disableAuthorizedMembers={true}
          />
        }
      >
        <ContainerHeader
          container={opinion}
          disableAuthorizedMembers={true}
        />
      </CollaborativeSecurity>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid size={6}>
          <OpinionDetails opinion={opinion} />
        </Grid>
        <Grid size={6}>
          <StixDomainObjectOverview stixDomainObject={opinion} displayOpinions={false} />
        </Grid>
        <Grid size={12}>
          <ContainerStixObjectsOrStixRelationships
            container={opinion}
            isSupportParticipation={true}
            enableReferences={enableReferences}
          />
        </Grid>
        <Grid size={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={opinion.id} />
        </Grid>
        <Grid size={6}>
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
