import { graphql } from 'relay-runtime';
import React from 'react';
import { useFragment } from 'react-relay';
import { Grid } from '@mui/material';
import useHelper from '../../../../utils/hooks/useHelper';
import { StixCyberObservable_stixCyberObservable$key } from './__generated__/StixCyberObservable_stixCyberObservable.graphql';
import StixCyberObservableDetails from './StixCyberObservableDetails';
import StixCyberObservableOverview from './StixCyberObservableOverview';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCyberObservableEdition from './StixCyberObservableEdition';

const stixCyberObservableFragment = graphql`
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
`;

interface StixCyberObservableProps {
  stixCyberObservableData: StixCyberObservable_stixCyberObservable$key;
}

const StixCyberObservable: React.FC<StixCyberObservableProps> = ({
  stixCyberObservableData,
}) => {
  const stixCyberObservable = useFragment<StixCyberObservable_stixCyberObservable$key>(
    stixCyberObservableFragment,
    stixCyberObservableData,
  );
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  return (
    <div data-testid='observable-details-page'>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={6}>
          <StixCyberObservableDetails
            stixCyberObservable={stixCyberObservable}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCyberObservableOverview
            stixCyberObservable={stixCyberObservable}
          />
        </Grid>
        <Grid item xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={stixCyberObservable.id}
            stixObjectOrStixRelationshipLink={`/dashboard/observations/observables/${stixCyberObservable.id}/knowledge`}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={stixCyberObservable.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={stixCyberObservable.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory
            stixCoreObjectId={stixCyberObservable.id}
          />
        </Grid>
        <Grid item xs={12}>
          <StixCoreObjectOrStixCoreRelationshipNotes
            stixCoreObjectOrStixCoreRelationshipId={stixCyberObservable.id}
            defaultMarkings={stixCyberObservable.objectMarking ?? []}
          />
        </Grid>
      </Grid>
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixCyberObservableEdition
            stixCyberObservableId={stixCyberObservable.id}
          />
        </Security>
      )}
    </div>
  );
};

export default StixCyberObservable;
