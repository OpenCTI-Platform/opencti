import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { AttackPattern_attackPattern$key } from '@private/components/techniques/attack_patterns/__generated__/AttackPattern_attackPattern.graphql';
import AttackPatternDetails from './AttackPatternDetails';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';
import { Grid } from '@components';

export const attackPatternFragment = graphql`
  fragment AttackPattern_attackPattern on AttackPattern {
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
    ...AttackPatternDetails_attackPattern
  }
  `;

interface AttackPatternProps {
  attackPatternData : AttackPattern_attackPattern$key
}

const AttackPattern: React.FC<AttackPatternProps> = ({ attackPatternData }) => {
  const attackPattern = useFragment<AttackPattern_attackPattern$key>(attackPatternFragment, attackPatternData);
  const overviewLayoutCustomization = useOverviewLayoutCustomization(attackPattern.entity_type);

  return (
    <div data-testid="attack-pattern-details-page">
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
                  <Grid key={key} size={width}>
                    <AttackPatternDetails attackPattern={attackPattern} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} size={width}>
                    <StixDomainObjectOverview stixDomainObject={attackPattern} />
                  </Grid>
                );
              case 'latestCreatedRelationships':
                return (
                  <Grid key={key} size={width}>
                    <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                      stixObjectOrStixRelationshipId={attackPattern.id}
                      stixObjectOrStixRelationshipLink={`/dashboard/techniques/attack_patterns/${attackPattern.id}/knowledge`}
                    />
                  </Grid>
                );
              case 'latestContainers':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectOrStixRelationshipLastContainers
                      stixCoreObjectOrStixRelationshipId={attackPattern.id}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={attackPattern.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={attackPattern.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={attackPattern.id}
                      defaultMarkings={attackPattern.objectMarking ?? []}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
    </div>
  );
};

export default AttackPattern;
