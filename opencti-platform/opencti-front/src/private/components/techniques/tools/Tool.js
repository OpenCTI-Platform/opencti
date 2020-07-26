import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import ToolOverview from './ToolOverview';
import ToolDetails from './ToolDetails';
import ToolEdition from './ToolEdition';
import ToolPopover from './ToolPopover';
import EntityLastReports from '../../reports/EntityLastReports';
import EntityStixCoreRelationshipsChart from '../../common/stix_core_relationships/EntityStixCoreRelationshipsChart';
import EntityReportsChart from '../../reports/EntityReportsChart';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
import StixCoreObjectNotes from '../../common/stix_core_objects/StixCoreObjectNotes';

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
    const { classes, tool } = this.props;
    return (
      <div className={classes.container}>
        <StixDomainObjectHeader
          stixDomainObject={tool}
          PopoverComponent={<ToolPopover />}
        />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
        >
          <Grid item={true} xs={3}>
            <ToolOverview tool={tool} />
          </Grid>
          <Grid item={true} xs={3}>
            <ToolDetails tool={tool} />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={tool.id} />
          </Grid>
        </Grid>
        <StixCoreObjectNotes entityId={tool.id} />
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 15 }}
        >
          <Grid item={true} xs={6}>
            <EntityStixCoreRelationshipsChart
              entityId={tool.id}
              relationship_type="uses"
            />
          </Grid>
          <Grid item={true} xs={6}>
            <EntityReportsChart entityId={tool.id} />
          </Grid>
        </Grid>
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
};

const Tool = createFragmentContainer(ToolComponent, {
  tool: graphql`
    fragment Tool_tool on Tool {
      id
      name
      aliases
      ...ToolOverview_tool
      ...ToolDetails_tool
    }
  `,
});

export default compose(inject18n, withStyles(styles))(Tool);
