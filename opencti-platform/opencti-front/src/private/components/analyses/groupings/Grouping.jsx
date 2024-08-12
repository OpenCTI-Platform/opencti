import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import useHelper from '../../../../utils/hooks/useHelper';
import GroupingDetails from './GroupingDetails';
import GroupingEdition from './GroupingEdition';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../external_references/StixCoreObjectExternalReferences';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const GroupingComponent = ({ grouping }) => {
  const classes = useStyles();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const overviewLayoutCustomization = useOverviewLayoutCustomization(grouping.entity_type);

  return (
    <div data-testid="grouping-details-page">
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <GroupingDetails grouping={grouping} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview
                      stixDomainObject={grouping}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={grouping.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={grouping.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
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
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <GroupingEdition groupingId={grouping.id} />
        </Security>
      )}
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
      ...GroupingDetails_grouping
      ...ContainerHeader_container
    }
  `,
});
