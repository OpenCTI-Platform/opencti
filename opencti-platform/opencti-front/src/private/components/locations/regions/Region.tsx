import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import LocationDetails from '@components/locations/LocationDetails';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';
import { Region_region$key } from './__generated__/Region_region.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

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
  const classes = useStyles();
  const region = useFragment<Region_region$key>(regionFragment, regionData);
  const countries = region.countries?.edges.map(
    (countryEdge) => countryEdge.node,
  );
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={4}>
          <LocationDetails locationData={region} />
        </Grid>
        <Grid item xs={4}>
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
        <Grid item xs={4}>
          <StixDomainObjectOverview
            stixDomainObject={region}
          />
        </Grid>
        <Grid item xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={region.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/regions/${region.id}/knowledge`}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={region.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={region.id} />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={region.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={region.id}
        defaultMarkings={region.objectMarking ?? []}
      />
    </>
  );
};

export default RegionComponent;
