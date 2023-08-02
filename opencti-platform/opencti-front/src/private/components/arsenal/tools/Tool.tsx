import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ToolDetails from './ToolDetails';
import ToolEdition from './ToolEdition';
import ToolPopover from './ToolPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships
  from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import { Tool_tool$key } from './__generated__/Tool_tool.graphql';
import StixCoreObjectOrStixRelationshipLastContainers
  from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const toolFragment = graphql`
    fragment Tool_tool on Tool {
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
        ...ToolDetails_tool
    }
`;

const ToolComponent = ({ tool }: { tool: Tool_tool$key }) => {
  const toolData = useFragment(toolFragment, tool);
  const classes = useStyles();
  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Tool'}
        stixDomainObject={toolData}
        PopoverComponent={<ToolPopover />}
        enableQuickSubscription
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <ToolDetails tool={toolData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={toolData} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={toolData.id}
            stixObjectOrStixRelationshipLink={`/dashboard/arsenal/tools/${toolData.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={toolData.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences stixCoreObjectId={toolData.id} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={toolData.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={toolData.id}
        defaultMarkings={(toolData.objectMarking?.edges ?? []).map((edge) => edge.node)}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ToolEdition toolId={toolData.id} />
      </Security>
    </div>
  );
};

export default ToolComponent;
