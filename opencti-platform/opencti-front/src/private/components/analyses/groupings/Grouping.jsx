import { Grid } from '@components';
import { createFragmentContainer, graphql } from 'react-relay';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import StixCoreObjectOrStixCoreRelationshipNotes from '../notes/StixCoreObjectOrStixCoreRelationshipNotes';
import GroupingDetails from './GroupingDetails';

const GroupingComponent = ({ grouping }) => {
  const overviewLayoutCustomization = useOverviewLayoutCustomization(grouping.entity_type);

  return (
    <div data-testid='grouping-details-page'>
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
                    <GroupingDetails grouping={grouping} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} size={width}>
                    <StixDomainObjectOverview
                      stixDomainObject={grouping}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={grouping.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={grouping.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={grouping.id}
                      defaultMarkings={grouping.objectMarking ?? []}
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

export default createFragmentContainer(GroupingComponent, {
  grouping: graphql`
    fragment Grouping_grouping on Grouping {
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
      status {
        id
        order
        template {
          name
          color
        }
      }
      workflowEnabled
      currentUserAccessRight
      ...GroupingDetails_grouping
      ...ContainerHeader_container
    }
  `,
});
