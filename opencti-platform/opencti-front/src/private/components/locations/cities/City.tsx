import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';
import { City_city$key } from './__generated__/City_city.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import LocationDetails from '../LocationDetails';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const cityFragment = graphql`
  fragment City_city on City {
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

const City = ({ cityData }: { cityData: City_city$key }) => {
  const classes = useStyles();
  const city = useFragment<City_city$key>(cityFragment, cityData);
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={4}>
          <LocationDetails locationData={city} />
        </Grid>
        <Grid item xs={4}>
          <LocationMiniMap
            center={
              city.latitude && city.longitude
                ? [city.latitude, city.longitude]
                : [48.8566969, 2.3514616]
            }
            city={city}
            zoom={5}
          />
        </Grid>
        <Grid item xs={4}>
          <StixDomainObjectOverview
            stixDomainObject={city}
          />
        </Grid>
        <Grid item xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={city.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/cities/${city.id}/knowledge`}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={city.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={city.id} />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={city.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={city.id}
        defaultMarkings={city.objectMarking ?? []}
      />
    </>
  );
};

export default City;
