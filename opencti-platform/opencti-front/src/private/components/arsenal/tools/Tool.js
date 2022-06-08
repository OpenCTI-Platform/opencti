import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';
import ToolDetails from './ToolDetails';
import ToolEdition from './ToolEdition';
import ToolPopover from './ToolPopover';
import StixCoreObjectOrStixCoreRelationshipLastReports from '../../analysis/reports/StixCoreObjectOrStixCoreRelationshipLastReports';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class ToolComponent extends Component {
  render() {
    const { classes, tool, enableReferences } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={tool}
          PopoverComponent={<ToolPopover />}
          enableReferences={enableReferences}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <StixDomainObjectOverview stixDomainObject={tool} />
          </Grid>
          <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
            <ToolDetails tool={tool} />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <SimpleStixObjectOrStixRelationshipStixCoreRelationships
              stixObjectOrStixRelationshipId={tool.id}
              stixObjectOrStixRelationshipLink={`/dashboard/arsenal/tools/${tool.id}/knowledge`}
            />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectOrStixCoreRelationshipLastReports
              stixCoreObjectOrStixCoreRelationshipId={tool.id}
            />
          </Grid>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 25 }}
        >
          <Grid item={true} xs={6}>
            <StixCoreObjectExternalReferences stixCoreObjectId={tool.id} />
          </Grid>
          <Grid item={true} xs={6}>
            <StixCoreObjectLatestHistory stixCoreObjectId={tool.id} />
          </Grid>
        </Grid>
        <StixCoreObjectOrStixCoreRelationshipNotes
          stixCoreObjectOrStixCoreRelationshipId={tool.id}
        />
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ToolEdition toolId={tool.id} />
        </Security>
      </div>
    );
  }
}

ToolComponent.propTypes = {
  tool: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  enableReferences: PropTypes.bool,
};

const Tool = createFragmentContainer(ToolComponent, {
  tool: graphql`
    fragment Tool_tool on Tool {
      id
      standard_id
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
      creator {
        id
        name
      }
      objectMarking {
        edges {
          node {
            id
            definition
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
  `,
});

export default compose(inject18n, withStyles(styles))(Tool);
