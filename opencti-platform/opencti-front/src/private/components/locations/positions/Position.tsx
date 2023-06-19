import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import PositionEdition from './PositionEdition';
import PositionPopover from './PositionPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import LocationMiniMap from '../../common/location/LocationMiniMap';
import PositionDetails, {
  positionDetailsLocationRelationshipsLinesQuery,
} from './PositionDetails';
import { Position_position$data } from './__generated__/Position_position.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery } from './__generated__/PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

interface PositionComponentProps {
  position: Position_position$data;
}

const PositionComponent: FunctionComponent<PositionComponentProps> = ({
  position,
}) => {
  const classes = useStyles();

  const queryRef = useQueryLoading<PositionDetailsLocationRelationshipsLinesQueryLinesPaginationQuery>(
    positionDetailsLocationRelationshipsLinesQuery,
    {
      count: 20,
      elementId: [position.id],
      relationship_type: ['located-at'],
    },
  );

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Position'}
        disableSharing={true}
        stixDomainObject={position}
        isOpenctiAlias={true}
        PopoverComponent={<PositionPopover />}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={4} style={{ paddingTop: 10 }}>
          {queryRef && (
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement} />}
            >
              <PositionDetails position={position} queryRef={queryRef} />
            </React.Suspense>
          )}
        </Grid>
        <Grid item={true} xs={4} style={{ paddingTop: 10 }}>
          <LocationMiniMap
            center={
              position.latitude && position.longitude
                ? [position.latitude, position.longitude]
                : [48.8566969, 2.3514616]
            }
            position={position}
            zoom={8}
          />
        </Grid>
        <Grid item={true} xs={4} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={position} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={position.id}
            stixObjectOrStixRelationshipLink={`/dashboard/locations/positions/${position.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={position.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences stixCoreObjectId={position.id} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={position.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={position.id}
        defaultMarkings={(position.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <PositionEdition positionId={position.id} />
      </Security>
    </div>
  );
};

const Position = createFragmentContainer(PositionComponent, {
  position: graphql`
    fragment Position_position on Position {
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
      description
      latitude
      longitude
      street_address
      postal_code
      city {
        id
        name
        description
      }
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
  `,
});

export default Position;
