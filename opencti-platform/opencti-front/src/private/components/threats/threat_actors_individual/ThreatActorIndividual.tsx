import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import ThreatActorIndividualBiographics from './ThreatActorIndividualBiographics';
import ThreatActorIndividualDemographics from './ThreatActorIndividualDemographics';
import ThreatActorIndividualDetails from './ThreatActorIndividualDetails';
import ThreatActorIndividualEdition from './ThreatActorIndividualEdition';
import {
  ThreatActorIndividual_ThreatActorIndividual$data,
  ThreatActorIndividual_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

export const threatActorIndividualFragment = graphql`
  fragment ThreatActorIndividual_ThreatActorIndividual on ThreatActorIndividual {
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
      definition
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
    eye_color
    hair_color
    height {
      date_seen
      measure
    }
    weight {
      date_seen
      measure
    }
    date_of_birth
    gender
    marital_status
    job_title
    bornIn {
      name
    }
    ethnicity {
      name
    }
    stixCoreRelationships {
      edges {
        node {
          relationship_type
          to {
            ... on Country {
              id
              name
            }
          }
        }
      }
    }
    ...ThreatActorIndividualDetails_ThreatActorIndividual
  }
`;

const hasDemographicsOrBiographics = (
  threatActorIndividual: ThreatActorIndividual_ThreatActorIndividual$data,
) => {
  if (
    threatActorIndividual?.eye_color
    || threatActorIndividual?.hair_color
    || threatActorIndividual?.date_of_birth
    || threatActorIndividual?.gender
    || threatActorIndividual?.marital_status
    || threatActorIndividual?.job_title
    || threatActorIndividual?.bornIn
    || threatActorIndividual?.ethnicity
    || (threatActorIndividual?.height
      && threatActorIndividual.height?.length > 0)
    || (threatActorIndividual?.weight && threatActorIndividual.weight?.length > 0)
  ) {
    return true;
  }
  for (const { node } of threatActorIndividual?.stixCoreRelationships?.edges
  ?? []) {
    const { relationship_type } = node ?? {};
    switch (relationship_type) {
      case 'resides-in':
      case 'citizen-of':
      case 'national-of':
        return true;
      default:
    }
  }
  return false;
};

interface ThreatActorIndividualProps {
  threatActorIndividualData: ThreatActorIndividual_ThreatActorIndividual$key;
}

const ThreatActorIndividual: React.FC<ThreatActorIndividualProps> = ({ threatActorIndividualData }) => {
  const threatActorIndividual = useFragment<ThreatActorIndividual_ThreatActorIndividual$key>(
    threatActorIndividualFragment,
    threatActorIndividualData,
  );
  const overviewLayoutCustomization = useOverviewLayoutCustomization(threatActorIndividual.entity_type);

  return (
    <>
      <Grid
        container
        columnSpacing={2}
        rowSpacing={3}
        style={{ marginBottom: 20 }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <ThreatActorIndividualDetails
                      threatActorIndividualData={threatActorIndividual}
                    />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview stixDomainObject={threatActorIndividual} />
                  </Grid>
                );
              case 'demographics':
                if (hasDemographicsOrBiographics(threatActorIndividual)) {
                  return (
                    <Grid key={key} item xs={width}>
                      <ThreatActorIndividualDemographics
                        threatActorIndividual={threatActorIndividual}
                      />
                    </Grid>
                  );
                }
                return undefined;
              case 'biographics':
                if (hasDemographicsOrBiographics(threatActorIndividual)) {
                  return (
                    <Grid key={key} item xs={width}>
                      <ThreatActorIndividualBiographics
                        threatActorIndividual={threatActorIndividual}
                      />
                    </Grid>
                  );
                }
                return undefined;
              case 'latestCreatedRelationships':
                return (
                  <Grid key={key} item xs={width}>
                    <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                      stixObjectOrStixRelationshipId={threatActorIndividual.id}
                      stixObjectOrStixRelationshipLink={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge`}
                    />
                  </Grid>
                );
              case 'latestContainers':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixRelationshipLastContainers
                      stixCoreObjectOrStixRelationshipId={threatActorIndividual.id}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={threatActorIndividual.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={threatActorIndividual.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={threatActorIndividual.id}
                      defaultMarkings={threatActorIndividual.objectMarking ?? []}
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
        <ThreatActorIndividualEdition
          threatActorIndividualId={threatActorIndividual.id}
        />
      </Security>
    </>
  );
};

export default ThreatActorIndividual;
