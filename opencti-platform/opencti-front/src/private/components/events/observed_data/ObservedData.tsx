import React from 'react';
import { Grid } from '@mui/material';
import { graphql, useFragment } from 'react-relay';
import ObservedDataDetails from './ObservedDataDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import ObservedDataEdition from './ObservedDataEdition';
import useHelper from '../../../../utils/hooks/useHelper';
import { ObservedData_observedData$key } from './__generated__/ObservedData_observedData.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const observedDataFragment = graphql`
  fragment ObservedData_observedData on ObservedData {
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
    ...ObservedDataDetails_observedData
    ...ContainerHeader_container
  }
`;

const ObservedData = ({
  observedDataKey,
}: {
  observedDataKey: ObservedData_observedData$key
}) => {
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const observedData = useFragment<ObservedData_observedData$key>(
    observedDataFragment,
    observedDataKey,
  );
  if (observedData) {
    return (
      <>
        <Grid
          container={true}
          spacing={3}
          style={{ marginBottom: 20 }}
        >
          <Grid item xs={6} style={{ paddingTop: 10 }}>
            <ObservedDataDetails observedData={observedData} />
          </Grid>
          <Grid item xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={observedData} />
          </Grid>
          <Grid item xs={6} style={{ marginTop: 30 }}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={observedData.id}
              stixObjectOrStixRelationshipLink={`/dashboard/events/observed_data/${observedData.id}/knowledge`}
            />
          </Grid>
          <Grid item xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectOrStixRelationshipLastContainers
              stixCoreObjectOrStixRelationshipId={observedData.id}
            />
          </Grid>
          <Grid item xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectExternalReferences
              stixCoreObjectId={observedData.id}
            />
          </Grid>
          <Grid item xs={6} style={{ marginTop: 30 }}>
            <StixCoreObjectLatestHistory stixCoreObjectId={observedData.id} />
          </Grid>
          <Grid item xs={12}>
            <StixCoreObjectOrStixCoreRelationshipNotes
              stixCoreObjectOrStixCoreRelationshipId={observedData.id}
              defaultMarkings={observedData.objectMarking ?? []}
            />
          </Grid>
        </Grid>
        {!isFABReplaced && (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <ObservedDataEdition observedDataId={observedData.id} />
          </Security>
        )}
      </>
    );
  }
  return (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default ObservedData;
