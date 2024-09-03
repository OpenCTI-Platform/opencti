import { graphql } from 'relay-runtime';
import React from 'react';
import { useFragment } from 'react-relay';
import { Grid } from '@mui/material';
import { Sector_sector$key } from './__generated__/Sector_sector.graphql';
import SectorDetails from './SectorDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import useHelper from '../../../../utils/hooks/useHelper';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SectorEdition from './SectorEdition';

const sectorFragment = graphql`
  fragment Sector_sector on Sector {
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
    ...SectorDetails_sector
  }
`;

interface SectorProps {
  sectorData: Sector_sector$key;
}

const Sector: React.FC<SectorProps> = ({ sectorData }) => {
  const sector = useFragment<Sector_sector$key>(
    sectorFragment,
    sectorData,
  );
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={6}>
          <SectorDetails sector={sector} />
        </Grid>
        <Grid item xs={6}>
          <StixDomainObjectOverview
            stixDomainObject={sector}
          />
        </Grid>
        <Grid item xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={sector.id}
            stixObjectOrStixRelationshipLink={`/dashboard/entities/sectors/${sector.id}/knowledge`}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={sector.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={sector.id} />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={sector.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={sector.id}
        defaultMarkings={sector.objectMarking ?? []}
      />
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <SectorEdition sectorId={sector.id} />
        </Security>
      )}
    </>
  );
};

export default Sector;
