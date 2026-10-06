import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import StixDomainObjectOverview from '../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ProvenanceSourcesCard from '../common/provenance/ProvenanceSourcesCard';
import useOverviewLayoutCustomization from '../../../utils/hooks/useOverviewLayoutCustomization';
import HuntDetails from './HuntDetails';
import HuntDraftBanner from './HuntDraftBanner';
import HuntLatestRuns from './HuntLatestRuns';
import HuntStatistics from './HuntStatistics';
import { Hunt_hunt$key } from './__generated__/Hunt_hunt.graphql';

const huntFragment = graphql`
  fragment Hunt_hunt on Hunt {
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
    hunt_status
    hunt_source_kind
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...HuntDetails_hunt
  }
`;

interface HuntProps {
  data: Hunt_hunt$key;
}

const Hunt = ({ data }: HuntProps) => {
  const hunt = useFragment(huntFragment, data);
  const overviewLayoutCustomization = useOverviewLayoutCustomization(hunt.entity_type);
  return (
    <div data-testid="hunt-overview">
      <HuntDraftBanner hunt={hunt} />
      <Grid container spacing={3} style={{ marginBottom: 20 }}>
        {overviewLayoutCustomization.map(({ key, width }) => {
          switch (key) {
            case 'details':
              return (
                <Grid key={key} item xs={width}>
                  <HuntDetails data={hunt} />
                </Grid>
              );
            case 'basicInformation':
              return (
                <Grid key={key} item xs={width}>
                  <StixDomainObjectOverview stixDomainObject={hunt} />
                </Grid>
              );
            case 'huntStatistics':
              return (
                <Grid key={key} item xs={width}>
                  <HuntStatistics huntId={hunt.id} />
                </Grid>
              );
            case 'latestRuns':
              return (
                <Grid key={key} item xs={width}>
                  <HuntLatestRuns huntId={hunt.id} />
                </Grid>
              );
            case 'externalReferences':
              return (
                <Grid key={key} item xs={width}>
                  <StixCoreObjectExternalReferences stixCoreObjectId={hunt.id} />
                </Grid>
              );
            case 'mostRecentHistory':
              return (
                <Grid key={key} item xs={width}>
                  <StixCoreObjectLatestHistory stixCoreObjectId={hunt.id} />
                </Grid>
              );
            case 'sources':
              return (
                <Grid key={key} item xs={width}>
                  <ProvenanceSourcesCard id={hunt.id} showEmpty />
                </Grid>
              );
            case 'notes':
              return (
                <Grid key={key} item xs={width}>
                  <StixCoreObjectOrStixCoreRelationshipNotes
                    stixCoreObjectOrStixCoreRelationshipId={hunt.id}
                    defaultMarkings={hunt.objectMarking ?? []}
                  />
                </Grid>
              );
            default:
              return null;
          }
        })}
      </Grid>
    </div>
  );
};

export default Hunt;
