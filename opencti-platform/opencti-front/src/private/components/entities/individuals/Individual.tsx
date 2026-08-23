import { useInitCreateRelationshipContext } from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import { Grid } from '@mui/material';
import React from 'react';
import { useFragment } from 'react-relay';
import { graphql } from 'relay-runtime';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import { Individual_individual$key } from './__generated__/Individual_individual.graphql';
import IndividualDetails from './IndividualDetails';

const individualFragment = graphql`
  fragment Individual_individual on Individual {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    spec_version
    revoked
    x_opencti_reliability
    confidence
    created
    modified
    created_at
    updated_at
    isUser
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
    ...WorkflowStatusStixDomainObject_data
    ...IndividualDetails_individual
  }
`;

interface IndividualProps {
  individualData: Individual_individual$key;
  viewAs: string;
}

const Individual: React.FC<IndividualProps> = ({
  individualData,
  viewAs,
}) => {
  useInitCreateRelationshipContext();

  const individual = useFragment<Individual_individual$key>(
    individualFragment,
    individualData,
  );
  const lastReportsProps = viewAs === 'knowledge'
    ? { stixCoreObjectOrStixRelationshipId: individual.id }
    : { authorId: individual.id };
  return (
    <div data-testid="individual-details-page">
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={6}>
          <IndividualDetails individual={individual} />
        </Grid>
        <Grid item xs={6}>
          <StixDomainObjectOverview
            stixDomainObject={individual}
          />
        </Grid>
        {viewAs === 'knowledge' && (
          <Grid item xs={6}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={individual.id}
              stixObjectOrStixRelationshipLink={`/dashboard/entities/individuals/${individual.id}/knowledge`}
            />
          </Grid>
        )}
        <Grid
          item
          xs={viewAs === 'knowledge' ? 6 : 12}
        >
          <StixCoreObjectOrStixRelationshipLastContainers
            {...lastReportsProps}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={individual.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={individual.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={individual.id}
        defaultMarkings={individual.objectMarking ?? []}
      />
    </div>
  );
};

export default Individual;
