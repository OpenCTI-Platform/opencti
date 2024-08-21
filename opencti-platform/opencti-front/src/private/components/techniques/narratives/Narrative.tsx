import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import { Narrative_narrative$key } from '@components/techniques/narratives/__generated__/Narrative_narrative.graphql';
import NarrativeDetails from './NarrativeDetails';
import NarrativeEdition from './NarrativeEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

export const narrativeFragment = graphql`
  fragment Narrative_narrative on Narrative {
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
    ...NarrativeDetails_narrative
  }
`;

interface NarrativeProps {
  narrativeData: Narrative_narrative$key
}

const Narrative: React.FC<NarrativeProps> = ({ narrativeData }) => {
  const narrative = useFragment<Narrative_narrative$key>(narrativeFragment, narrativeData);
  const overviewLayoutCustomization = useOverviewLayoutCustomization(narrative.entity_type);

  return (
    <>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <NarrativeDetails narrative={narrative} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview stixDomainObject={narrative} />
                  </Grid>
                );
              case 'latestCreatedRelationships':
                return (
                  <Grid key={key} item xs={width}>
                    <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                      stixObjectOrStixRelationshipId={narrative.id}
                      stixObjectOrStixRelationshipLink={`/dashboard/techniques/narratives/${narrative.id}/knowledge`}
                    />
                  </Grid>
                );
              case 'latestContainers':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixRelationshipLastContainers
                      stixCoreObjectOrStixRelationshipId={narrative.id}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={narrative.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={narrative.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={narrative.id}
                      defaultMarkings={narrative.objectMarking ?? []}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <NarrativeEdition narrativeId={narrative.id} />
      </Security>
    </>
  );
};

export default Narrative;
