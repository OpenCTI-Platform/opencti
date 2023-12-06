import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import ThreatActorIndividualBiographics from './ThreatActorIndividualBiographics';
import ThreatActorIndividualDemographics from './ThreatActorIndividualDemographics';
import ThreatActorIndividualDetails from './ThreatActorIndividualDetails';
import {
  ThreatActorIndividual_ThreatActorIndividual$data,
  ThreatActorIndividual_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

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

const ThreatActorIndividualComponent = ({
  data,
}: {
  data: ThreatActorIndividual_ThreatActorIndividual$key;
}) => {
  const classes = useStyles();
  const threatActorIndividual = useFragment<ThreatActorIndividual_ThreatActorIndividual$key>(
    threatActorIndividualFragment,
    data,
  );
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <ThreatActorIndividualDetails
            threatActorIndividualData={threatActorIndividual}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={threatActorIndividual} />
        </Grid>
        {hasDemographicsOrBiographics(threatActorIndividual) && (
          <>
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
              <ThreatActorIndividualDemographics
                threatActorIndividual={threatActorIndividual}
              />
            </Grid>
            <Grid item={true} xs={6} style={{ marginTop: 30 }}>
              <ThreatActorIndividualBiographics
                threatActorIndividual={threatActorIndividual}
              />
            </Grid>
          </>
        )}
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={threatActorIndividual.id}
            stixObjectOrStixRelationshipLink={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={threatActorIndividual.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={threatActorIndividual.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory
            stixCoreObjectId={threatActorIndividual.id}
          />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={threatActorIndividual.id}
        defaultMarkings={threatActorIndividual.objectMarking ?? []}
      />
    </>
  );
};

export default ThreatActorIndividualComponent;
