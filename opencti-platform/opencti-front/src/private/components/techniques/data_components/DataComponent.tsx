import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Grid from '@mui/material/Grid';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import DataComponentPopover from './DataComponentPopover';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import DataComponentEdition from './DataComponentEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import DataComponentDetails from './DataComponentDetails';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import { DataComponent_dataComponent$key } from './__generated__/DataComponent_dataComponent.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const DataComponentFragment = graphql`
  fragment DataComponent_dataComponent on DataComponent {
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
    aliases
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...DataComponentDetails_dataComponent
  }
`;

const DataComponent: FunctionComponent<{
  data: DataComponent_dataComponent$key;
}> = ({ data }) => {
  const classes = useStyles();

  const dataComponent = useFragment(DataComponentFragment, data);

  return (
    <div>
      <StixDomainObjectHeader
        entityType={'Data-Component'}
        stixDomainObject={dataComponent}
        PopoverComponent={
          <DataComponentPopover dataComponentId={dataComponent.id} />
        }
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <DataComponentDetails dataComponent={dataComponent} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={dataComponent} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={dataComponent.id}
            stixObjectOrStixRelationshipLink={`/dashboard/techniques/data_components/${dataComponent.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={dataComponent.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={dataComponent.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={dataComponent.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={dataComponent.id}
        defaultMarkings={(dataComponent.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <DataComponentEdition dataComponentId={dataComponent.id} />
      </Security>
    </div>
  );
};

export default DataComponent;
