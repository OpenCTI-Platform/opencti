import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import AdministrativeAreaEdition from './AdministrativeAreaEdition';
import AdministrativeAreaPopover from './AdministrativeAreaPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { AdministrativeArea_administrativeArea$key } from './__generated__/AdministrativeArea_administrativeArea.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
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
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Administrative-Area'}
        disableSharing={true}
        stixDomainObject={administrativeArea}
        isOpenctiAlias={true}
        PopoverComponent={AdministrativeAreaPopover}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
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
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={administrativeArea} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={administrativeArea.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={administrativeArea.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={administrativeArea.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory
            stixCoreObjectId={administrativeArea.id}
          />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={administrativeArea.id}
        defaultMarkings={(administrativeArea.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <AdministrativeAreaEdition
          administrativeAreaId={administrativeArea.id}
        />
      </Security>
    </div>
  );
};

export default AdministrativeArea;
