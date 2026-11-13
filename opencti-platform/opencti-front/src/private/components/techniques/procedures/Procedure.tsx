import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import { PATH_PROCEDURE } from '@components/common/routes/paths';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';
import ProcedureDetails from './ProcedureDetails';
import { Procedure_procedure$key } from './__generated__/Procedure_procedure.graphql';

const ProcedureFragment = graphql`
  fragment Procedure_procedure on Procedure {
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
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...WorkflowStatusStixDomainObject_data
    ...ProcedureDetails_procedure
  }
`;

interface ProcedureProps {
  procedureData: Procedure_procedure$key;
}

const Procedure: React.FC<ProcedureProps> = ({ procedureData }) => {
  const procedure = useFragment<Procedure_procedure$key>(ProcedureFragment, procedureData);
  const overviewLayoutCustomization = useOverviewLayoutCustomization(procedure.entity_type);

  return (
    <div data-testid="procedure-details-page">
      <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
        {overviewLayoutCustomization.map(({ key, width }) => {
          switch (key) {
            case 'details':
              return (
                <Grid key={key} size={width}>
                  <ProcedureDetails procedure={procedure} />
                </Grid>
              );
            case 'basicInformation':
              return (
                <Grid key={key} size={width}>
                  <StixDomainObjectOverview stixDomainObject={procedure} />
                </Grid>
              );
            case 'latestCreatedRelationships':
              return (
                <Grid key={key} size={width}>
                  <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                    stixObjectOrStixRelationshipId={procedure.id}
                    stixObjectOrStixRelationshipLink={`${PATH_PROCEDURE(procedure.id)}/knowledge`}
                  />
                </Grid>
              );
            case 'latestContainers':
              return (
                <Grid key={key} size={width}>
                  <StixCoreObjectOrStixRelationshipLastContainers
                    stixCoreObjectOrStixRelationshipId={procedure.id}
                  />
                </Grid>
              );
            case 'externalReferences':
              return (
                <Grid key={key} size={width}>
                  <StixCoreObjectExternalReferences stixCoreObjectId={procedure.id} />
                </Grid>
              );
            case 'mostRecentHistory':
              return (
                <Grid key={key} size={width}>
                  <StixCoreObjectLatestHistory stixCoreObjectId={procedure.id} />
                </Grid>
              );
            case 'notes':
              return (
                <Grid key={key} size={width}>
                  <StixCoreObjectOrStixCoreRelationshipNotes
                    stixCoreObjectOrStixCoreRelationshipId={procedure.id}
                    defaultMarkings={procedure.objectMarking ?? []}
                  />
                </Grid>
              );
            default:
              return null;
          }
        })}
      </Grid>
    </div>
  );
};

export default Procedure;
