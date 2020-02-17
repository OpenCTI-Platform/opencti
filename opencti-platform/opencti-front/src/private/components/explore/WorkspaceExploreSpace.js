import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  assoc, compose, dissoc, indexBy, map, prop, propOr, values,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Responsive, WidthProvider } from 'react-grid-layout';
import { withStyles } from '@material-ui/core/styles';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import Drawer from '@material-ui/core/Drawer';
import Grid from '@material-ui/core/Grid';
import { DatePicker } from '@material-ui/pickers';
import inject18n from '../../../components/i18n';
import { commitMutation } from '../../../relay/environment';
import { parse } from '../../../utils/Time';
import { workspaceMutationFieldPatch } from '../workspaces/WorkspaceEditionOverview';
import ExploreAddWidget from './ExploreAddWidget';
import ExploreUpdateWidget from './ExploreUpdateWidget';
import VictimologyDistribution from './VictimologyDistribution';
import VictimologyTimeseries from './VictimologyTimeseries';
import CampaignsTimeseries from './CampaignsTimeseries';
import IncidentsTimeseries from './IncidentsTimeseries';
import AttackPatternsDistribution from './AttackPatternsDistribution';
import Security, { EXPLORE_EXUPDATE } from '../../../utils/Security';

const styles = (theme) => ({
  container: {
    margin: '0 0 80px 0',
    padding: 0,
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
});

const ResponsiveReactGridLayout = WidthProvider(Responsive);

class WorkspaceExploreSpaceComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { openConfig: false, currentWidget: {} };
  }

  saveWorkspace(workspaceData) {
    const JSONData = JSON.stringify(workspaceData);
    commitMutation({
      mutation: workspaceMutationFieldPatch,
      variables: {
        id: this.props.workspace.id,
        input: {
          key: 'workspace_data',
          value: Buffer.from(JSONData).toString('base64'),
        },
      },
    });
  }

  decodeWorkspaceData() {
    const { workspace } = this.props;
    let workspaceData = { widgets: {}, config: { inferred: true } };
    if (workspace.workspace_data && workspace.workspace_data.length > 0) {
      workspaceData = JSON.parse(
        Buffer.from(workspace.workspace_data, 'base64').toString('ascii'),
      );
    }
    return workspaceData;
  }

  handleAddWidget(newValues) {
    const workspaceData = this.decodeWorkspaceData();
    const finalWorkspaceData = assoc(
      'widgets',
      assoc(
        newValues.id,
        assoc(
          'layout',
          {
            i: newValues.id,
            x: 0,
            y: 0,
            w: 4,
            h: 4,
            minW: 2,
            minH: 2,
          },
          newValues,
        ),
        workspaceData.widgets,
      ),
      workspaceData,
    );
    this.saveWorkspace(finalWorkspaceData);
  }

  handleUpdateWidget(newValues) {
    const workspaceData = this.decodeWorkspaceData();
    const finalWorkspaceData = assoc(
      'widgets',
      assoc(newValues.id, newValues, workspaceData.widgets),
      workspaceData,
    );
    this.saveWorkspace(finalWorkspaceData);
  }

  handleDeleteWidget(widgetId) {
    const workspaceData = this.decodeWorkspaceData();
    const finalWorkspaceData = assoc(
      'widgets',
      dissoc(widgetId, workspaceData.widgets),
      workspaceData,
    );
    this.saveWorkspace(finalWorkspaceData);
  }

  onLayoutChange(layouts) {
    // TODO @SAM / @JRI Find a way to not trigger that on first display...
    const workspaceData = this.decodeWorkspaceData();
    const layoutsObject = indexBy(prop('i'), layouts);
    const finalWorkspaceData = assoc(
      'widgets',
      map((n) => assoc('layout', layoutsObject[n.id], n), workspaceData.widgets),
      workspaceData,
    );
    this.saveWorkspace(finalWorkspaceData);
  }

  handleDateChange(type, value) {
    const workspaceData = this.decodeWorkspaceData();
    const finalWorkspaceData = assoc(
      'config',
      assoc(type, value ? parse(value).format() : null, workspaceData.config),
      workspaceData,
    );
    this.saveWorkspace(finalWorkspaceData);
  }

  handleChangeInferred() {
    const workspaceData = this.decodeWorkspaceData();
    const finalWorkspaceData = assoc(
      'config',
      assoc('inferred', !workspaceData.config.inferred, workspaceData.config),
      workspaceData,
    );
    this.saveWorkspace(finalWorkspaceData);
  }

  handleOpenConfig(config) {
    this.setState({ openConfig: true, currentWidget: config });
  }

  handleCloseConfig() {
    this.setState({ openConfig: false, currentWidget: {} });
  }

  render() {
    const { classes, t } = this.props;
    const workspaceData = this.decodeWorkspaceData();
    return (
      <div className={classes.container}>
        <Drawer anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}>
          <Grid container={true} spacing={1}>
            <Grid item={true} xs="auto">
              <DatePicker
                value={propOr(null, 'startDate', workspaceData.config)}
                disableToolbar={true}
                format="YYYY-MM-DD"
                autoOk={true}
                label={t('Start date')}
                clearable={true}
                disableFuture={true}
                onChange={this.handleDateChange.bind(this, 'startDate')}
              />
            </Grid>
            <Grid item={true} xs="auto">
              <DatePicker
                value={propOr(null, 'endDate', workspaceData.config)}
                disableToolbar={true}
                format="YYYY-MM-DD"
                autoOk={true}
                label={t('End date')}
                clearable={true}
                disableFuture={true}
                onChange={this.handleDateChange.bind(this, 'endDate')}
              />
            </Grid>
            <Grid item={true} xs="auto">
              <FormControlLabel
                style={{ paddingTop: 5, marginRight: 15 }}
                control={
                  <Switch
                    checked={propOr(false, 'inferred', workspaceData.config)}
                    onChange={this.handleChangeInferred.bind(this)}
                    color="primary"
                  />
                }
                label={t('Inferences')}
              />
            </Grid>
          </Grid>
        </Drawer>
        <ResponsiveReactGridLayout
          className="layout"
          cols={{
            lg: 12, md: 10, sm: 6, xs: 4, xxs: 2,
          }}
          rowHeight={100}
          isDraggable={false}
          isResizable={false}
          onLayoutChange={this.onLayoutChange.bind(this)}>
          {map((widget) => {
            switch (widget.widget) {
              case 'VictimologyDistribution':
                return (
                  <div key={widget.id} data-grid={widget.layout}>
                    <VictimologyDistribution
                      configuration={widget}
                      handleOpenConfig={this.handleOpenConfig.bind(this)}
                      inferred={workspaceData.config.inferred}
                      startDate={workspaceData.config.startDate}
                      endDate={workspaceData.config.endDate}
                    />
                  </div>
                );
              case 'VictimologyTimeseries':
                return (
                  <div key={widget.id} data-grid={widget.layout}>
                    <VictimologyTimeseries
                      configuration={widget}
                      handleOpenConfig={this.handleOpenConfig.bind(this)}
                      inferred={workspaceData.config.inferred}
                      startDate={workspaceData.config.startDate}
                      endDate={workspaceData.config.endDate}
                    />
                  </div>
                );
              case 'CampaignsTimeseries':
                return (
                  <div key={widget.id} data-grid={widget.layout}>
                    <CampaignsTimeseries
                      configuration={widget}
                      handleOpenConfig={this.handleOpenConfig.bind(this)}
                      inferred={workspaceData.config.inferred}
                      startDate={workspaceData.config.startDate}
                      endDate={workspaceData.config.endDate}
                    />
                  </div>
                );
              case 'IncidentsTimeseries':
                return (
                  <div key={widget.id} data-grid={widget.layout}>
                    <IncidentsTimeseries
                      configuration={widget}
                      handleOpenConfig={this.handleOpenConfig.bind(this)}
                      inferred={workspaceData.config.inferred}
                      startDate={workspaceData.config.startDate}
                      endDate={workspaceData.config.endDate}
                    />
                  </div>
                );
              case 'AttackPatternsDistribution':
                return (
                  <div key={widget.id} data-grid={widget.layout}>
                    <AttackPatternsDistribution
                      configuration={widget}
                      handleOpenConfig={this.handleOpenConfig.bind(this)}
                      inferred={workspaceData.config.inferred}
                      startDate={workspaceData.config.startDate}
                      endDate={workspaceData.config.endDate}
                    />
                  </div>
                );
              default:
                return <div />;
            }
          }, values(workspaceData.widgets))}
        </ResponsiveReactGridLayout>
        <ExploreUpdateWidget
          open={this.state.openConfig}
          configuration={this.state.currentWidget}
          handleClose={this.handleCloseConfig.bind(this)}
          handleUpdate={this.handleUpdateWidget.bind(this)}
          handleDelete={this.handleDeleteWidget.bind(this)}
        />
        <Security needs={[EXPLORE_EXUPDATE]}>
          <ExploreAddWidget onAdd={this.handleAddWidget.bind(this)} />
        </Security>
      </div>
    );
  }
}

WorkspaceExploreSpaceComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const WorkspaceExploreSpace = createFragmentContainer(
  WorkspaceExploreSpaceComponent,
  {
    workspace: graphql`
      fragment WorkspaceExploreSpace_workspace on Workspace {
        id
        workspace_data
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(WorkspaceExploreSpace);
