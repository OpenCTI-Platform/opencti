import React from 'react';
import { graphql, useFragment } from 'react-relay';
import LocationDetails from '@private/components/locations/LocationDetails';
import { Grid } from '@components';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';
import { Region_region$key } from './__generated__/Region_region.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const regionFragment = graphql`
  fragment Region_region on Region {
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
    countries {
      edges {
        node {
          name
          x_opencti_aliases
        }
      }
    }
    name
    latitude
    longitude
    x_opencti_aliases
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...LocationDetails_location
  }
`;

const RegionComponent = ({ regionData }: { regionData: Region_region$key }) => {
  const region = useFragment<Region_region$key>(regionFragment, regionData);
  const countries = region.countries?.edges.map(
    (countryEdge) => countryEdge.node,
  );
  return (
    <div data-testid="region-details-page">
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid size={4}>
          <LocationDetails locationData={region} />
        </Grid>
        <Grid size={4}>
          <LocationMiniMap
            center={
              region.latitude && region.longitude
                ? [region.latitude, region.longitude]
                : [48.8566969, 2.3514616]
            }
            countries={countries}
            zoom={3}
          />
        </Grid>
        <Grid size={4}>
          <StixDomainObjectOverview
            stixDomainObject={region}
          />
        </Grid>
        <Grid size={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={region.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/regions/${region.id}/knowledge`}
          />
        </Grid>
        <Grid size={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={region.id}
          />
        </Grid>
        <Grid size={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={region.id} />
        </Grid>
        <Grid size={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={region.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={region.id}
        defaultMarkings={region.objectMarking ?? []}
      />
    </div>
  );
};

export default RegionComponent;
