import { graphql } from 'relay-runtime';
import React from 'react';
import { useFragment } from 'react-relay';
import { Grid } from '@mui/material';
import { SecurityPlatform_securityPlatform$key } from '@components/entities/securityPlatforms/__generated__/SecurityPlatform_securityPlatform.graphql';
import SecurityPlatformDetails from '@components/entities/securityPlatforms/SecurityPlatformDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

export const securityPlatformFragment = graphql`
  fragment SecurityPlatform_securityPlatform on SecurityPlatform {
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
#        ...SecurityPlatformDetails_securityPlatform
  }
`;

interface SecurityPlatformProps {
  securityPlatformData: SecurityPlatform_securityPlatform$key;
}

const SecurityPlatform: React.FC<SecurityPlatformProps> = ({ securityPlatformData }) => {
  const securityPlatform = useFragment<SecurityPlatform_securityPlatform$key>(
    securityPlatformFragment,
    securityPlatformData,
  );
  const overviewLayoutCustomization = useOverviewLayoutCustomization(securityPlatform.entity_type);

  return (
    <>
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <SecurityPlatformDetails securityPlatform={securityPlatform} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview stixDomainObject={securityPlatform} />
                  </Grid>
                );
              case 'latestCreatedRelationships':
                return (
                  <Grid key={key} item xs={width}>
                    <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                      stixObjectOrStixRelationshipId={securityPlatform.id}
                      stixObjectOrStixRelationshipLink={`/dashboard/entities/security_platform/${securityPlatform.id}/knowledge`}
                    />
                  </Grid>
                );
              case 'latestContainers':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixRelationshipLastContainers
                      stixCoreObjectOrStixRelationshipId={securityPlatform.id}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={securityPlatform.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={securityPlatform.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={securityPlatform.id}
                      defaultMarkings={securityPlatform.objectMarking ?? []}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
    </>
  );
};

export default SecurityPlatform;
