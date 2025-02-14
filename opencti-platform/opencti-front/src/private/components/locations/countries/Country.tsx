import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid2';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';
import { Country_country$key } from './__generated__/Country_country.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

export const getCountriesQuery = graphql`
  query CountryGetAllQuery {
    countries (first:5000) {
      edges {
        node {
          id
          name
        }
      }
    }
  }
`;

export const countryFragment = graphql`
  fragment Country_country on Country {
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
  }
`;

const CountryComponent = ({
  countryData,
}: {
  countryData: Country_country$key;
}) => {
  const classes = useStyles();
  const country = useFragment<Country_country$key>(
    countryFragment,
    countryData,
  );
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid size={{ xs: 1 }}>
          <LocationMiniMap
            center={
              country.latitude && country.longitude
                ? [country.latitude, country.longitude]
                : [48.8566969, 2.3514616]
            }
            countries={[country]}
            zoom={4}
          />
        </Grid>
        <Grid size={{ xs: 1 }}>
          <StixDomainObjectOverview
            stixDomainObject={country}
          />
        </Grid>
        <Grid size={{ xs: 1 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={country.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/countries/${country.id}/knowledge`}
          />
        </Grid>
        <Grid size={{ xs: 1 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={country.id}
          />
        </Grid>
        <Grid size={{ xs: 1 }}>
          <StixCoreObjectExternalReferences stixCoreObjectId={country.id} />
        </Grid>
        <Grid size={{ xs: 1 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={country.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={country.id}
        defaultMarkings={country.objectMarking ?? []}
      />
    </>
  );
};

export default CountryComponent;
