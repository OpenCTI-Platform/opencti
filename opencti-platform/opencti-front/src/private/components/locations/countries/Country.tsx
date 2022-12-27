import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import CountryEdition from './CountryEdition';
import CountryPopover from './CountryPopover';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';
import { Country_country$key } from './__generated__/Country_country.graphql';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
  },
}));

export const countryFragment = graphql`
  fragment Country_country on Country {
    id
    standard_id
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
      }
    }
    creator {
      id
      name
    }
    objectMarking {
      edges {
        node {
          id
          definition_type
          definition
          x_opencti_order
          x_opencti_color
        }
      }
    }
    objectLabel {
      edges {
        node {
          id
          value
          color
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
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Country'}
        disableSharing={true}
        stixDomainObject={country}
        isOpenctiAlias={true}
        PopoverComponent={CountryPopover}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
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
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={country} />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={country.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/countries/${country.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectOrStixCoreRelationshipLastReports
            stixCoreObjectOrStixCoreRelationshipId={country.id}
          />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={country.id} />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={country.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={country.id}
        defaultMarking={(country.objectMarking?.edges ?? []).map((edge) => edge.node)}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CountryEdition countryId={country.id} />
      </Security>
    </div>
  );
};

export default CountryComponent;
