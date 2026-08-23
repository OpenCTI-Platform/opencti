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
import { Organization_organization$key } from './__generated__/Organization_organization.graphql';
import OrganizationDetails from './OrganizationDetails';

const organizationFragment = graphql`
  fragment Organization_organization on Organization {
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
    ...OrganizationDetails_organization
  }
`;

interface OrganizationProps {
  organizationData: Organization_organization$key;
  viewAs: string;
}

const Organization: React.FC<OrganizationProps> = ({
  organizationData,
  viewAs,
}) => {
  useInitCreateRelationshipContext();

  const organization = useFragment<Organization_organization$key>(
    organizationFragment,
    organizationData,
  );
  const lastReportsProps = viewAs === 'knowledge'
    ? { stixCoreObjectOrStixRelationshipId: organization.id }
    : { authorId: organization.id };
  return (
    <div data-testid="organization-details-page">
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        <Grid item xs={6}>
          <OrganizationDetails organizationData={organization} />
        </Grid>
        <Grid item xs={6}>
          <StixDomainObjectOverview
            stixDomainObject={organization}
          />
        </Grid>
        {viewAs === 'knowledge' && (
          <Grid item xs={6}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={organization.id}
              stixObjectOrStixRelationshipLink={`/dashboard/entities/organizations/${organization.id}/knowledge`}
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
            stixCoreObjectId={organization.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={organization.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={organization.id}
        defaultMarkings={organization.objectMarking ?? []}
      />
    </div>
  );
};

export default Organization;
