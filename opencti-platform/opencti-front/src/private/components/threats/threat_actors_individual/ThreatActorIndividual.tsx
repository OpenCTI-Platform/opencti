import React, { Fragment } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
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

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
    display: 'inline-flex',
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

const renderTemplateElement: (key: string, width: number, threatActorIndividual: unknown) => null = (key, width, threatActorIndividual) => {
  switch (key) {
    case 'details':
      return (
        <ThreatActorIndividualDetails
          threatActorIndividualData={threatActorIndividual}
        />
      );
    case 'basicInformation':
      return (
        <StixDomainObjectOverview stixDomainObject={threatActorIndividual} />
      );
    case 'demographics':
      return (
        <Fragment key={'demographics'} >
          { hasDemographicsOrBiographics(threatActorIndividual) && (
            <ThreatActorIndividualDemographics
              threatActorIndividual={threatActorIndividual}
            />
          ) }
        </Fragment>
      );
    case 'biographics':
      return (
        <Fragment key={'biographics'} >
          { hasDemographicsOrBiographics(threatActorIndividual) && (
            <ThreatActorIndividualBiographics
              threatActorIndividual={threatActorIndividual}
            />
          ) }
        </Fragment>
      );
    case 'latestCreatedRelationships':
      return (
        <SimpleStixObjectOrStixRelationshipStixCoreRelationships
          stixObjectOrStixRelationshipId={threatActorIndividual.id}
          stixObjectOrStixRelationshipLink={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge`}
        />
      );
    case 'latestContainers':
      return (
        <StixCoreObjectOrStixRelationshipLastContainers
          stixCoreObjectOrStixRelationshipId={threatActorIndividual.id}
        />
      );
    case 'externalReferences':
      return (
        <StixCoreObjectExternalReferences
          stixCoreObjectId={threatActorIndividual.id}
        />
      );
    case 'mostRecentHistory':
      return (
        <StixCoreObjectLatestHistory
          stixCoreObjectId={threatActorIndividual.id}
        />
      );
    case 'notes':
      return (
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={threatActorIndividual.id}
          defaultMarkings={threatActorIndividual.objectMarking ?? []}
        />
      );
    default:
      return null;
  }
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
  const threatActorIndividualOverviewLayoutCustomization = useOverviewLayoutCustomization(threatActorIndividual.entity_type);
  return (
    <>
      <Grid
        container
        columnSpacing={2}
        rowSpacing={3}
        classes={{ container: classes.gridContainer }}
      >
        {// a faire dans le hook
          Array.from(threatActorIndividualOverviewLayoutCustomization.entries()).map(([key, { width }]) => {
            return (
              <Grid key={'threatActorIndividualOverviewLayoutCustomization'} item xs={width}>
                {
                  renderTemplateElement(key, width, threatActorIndividual)
                }
              </Grid>
            );
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

export default ThreatActorIndividualComponent;
