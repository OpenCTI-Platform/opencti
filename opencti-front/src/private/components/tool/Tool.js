import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../components/i18n';
import ToolHeader from './ToolHeader';
import ToolOverview from './ToolOverview';
import ToolEdition from './ToolEdition';
import EntityLastReports from '../report/EntityLastReports';
import EntityStixRelationsChart from '../stix_relation/EntityStixRelationsChart';
import EntityReportsChart from '../report/EntityReportsChart';
import EntityStixRelationsRadar from '../stix_relation/EntityStixRelationsRadar';

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
        <ToolHeader tool={tool}/>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }}>
          <Grid item={true} xs={6}>
            <ToolOverview tool={tool}/>
          </Grid>
          <Grid item={true} xs={6}>
            <EntityLastReports entityId={tool.id}/>
          </Grid>
        </Grid>
        <Grid container={true} spacing={32} classes={{ container: classes.gridContainer }} style={{ marginTop: 20 }}>
          <Grid item={true} xs={4}>
            <EntityStixRelationsChart entityId={tool.id} relationType='uses' />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityStixRelationsRadar
              entityId={tool.id}
              entityType='Kill-Chain-Phase'
              relationType='kill_chain_phases'
              field='phase_name'
              resolveInferences={true}
            />
          </Grid>
          <Grid item={true} xs={4}>
            <EntityReportsChart entityId={tool.id}/>
          </Grid>
        </Grid>
        <ToolEdition toolId={tool.id}/>
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
          ...ToolHeader_tool
          ...ToolOverview_tool
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(Tool);
