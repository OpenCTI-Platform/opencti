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
import { AdministrativeArea_administrativeArea$key } from './__generated__/AdministrativeArea_administrativeArea.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const administrativeAreaFragment = graphql`
  fragment AdministrativeArea_administrativeArea on AdministrativeArea {
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

const AdministrativeArea = ({
  administrativeAreaData,
}: {
  administrativeAreaData: AdministrativeArea_administrativeArea$key;
}) => {
  const classes = useStyles();
  const administrativeArea = useFragment<AdministrativeArea_administrativeArea$key>(
    administrativeAreaFragment,
    administrativeAreaData,
  );
  return (
    <div data-testid="administrative-area-details-page">
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={4}>
          <LocationDetails locationData={administrativeArea} />
        </Grid>
        <Grid item xs={4}>
          <LocationMiniMap
            center={
              administrativeArea.latitude && administrativeArea.longitude
                ? [administrativeArea.latitude, administrativeArea.longitude]
                : [48.8566969, 2.3514616]
            }
            administrativeArea={administrativeArea}
            zoom={5}
          />
        </Grid>
        <Grid item xs={4}>
          <StixDomainObjectOverview
            stixDomainObject={administrativeArea}
          />
        </Grid>
        <Grid item xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={administrativeArea.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={administrativeArea.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={administrativeArea.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory
            stixCoreObjectId={administrativeArea.id}
          />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={administrativeArea.id}
        defaultMarkings={administrativeArea.objectMarking ?? []}
      />
    </div>
  );
};

export default AdministrativeArea;
