import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import CityEdition from './CityEdition';
import CityPopover from './CityPopover';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { City_city$key } from './__generated__/City_city.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const cityFragment = graphql`
  fragment City_city on City {
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
    creators {
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

const City = ({ cityData }: { cityData: City_city$key }) => {
  const classes = useStyles();

  const city = useFragment<City_city$key>(cityFragment, cityData);

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'City'}
        disableSharing={true}
        stixDomainObject={city}
        isOpenctiAlias={true}
        PopoverComponent={CityPopover}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
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
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={city} />
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
            stixObjectOrStixRelationshipId={city.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/cities/${city.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectOrStixCoreRelationshipLastReports
            stixCoreObjectOrStixCoreRelationshipId={city.id}
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
          <StixCoreObjectExternalReferences stixCoreObjectId={city.id} />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={city.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={city.id}
        defaultMarking={(city.objectMarking?.edges ?? []).map((edge) => edge.node)}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <CityEdition cityId={city.id} />
      </Security>
    </div>
  );
};

export default City;
