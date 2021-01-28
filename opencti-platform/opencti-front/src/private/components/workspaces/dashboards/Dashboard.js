import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Responsive, WidthProvider } from 'react-grid-layout';
import { DatePicker } from '@material-ui/pickers';
import Drawer from '@material-ui/core/Drawer';
import Grid from '@material-ui/core/Grid';
import InputLabel from '@material-ui/core/InputLabel';
import MenuItem from '@material-ui/core/MenuItem';
import FormControl from '@material-ui/core/FormControl';
import Select from '@material-ui/core/Select';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import {
  daysAgo,
  monthsAgo,
  parse,
  yearsAgo,
  now,
} from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import WorkspaceHeader from '../WorkspaceHeader';
import { commitMutation } from '../../../../relay/environment';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import WidgetCreation from './WidgetCreation';
import Security, { EXPLORE_EXUPDATE } from '../../../../utils/Security';
import ThreatVictimologyAll from './ThreatVictimologyAll';
import ThreatVictimologySectors from './ThreatVictimologySectors';
import ThreatVictimologyCountries from './ThreatVictimologyCountries';
import ThreatActivityCampaigns from './ThreatActivityCampaigns';
import ThreatActivityIndicators from './ThreatActivityIndicators';
import ThreatActivityReports from './ThreatActivityReports';
import EntityThreatsAll from './EntityThreatsAll';
import EntityThreatsIntrusionSets from './EntityThreatsIntrusionSets';
import EntityThreatsMalwares from './EntityThreatsMalwares';
import EntityActivityCampaigns from './EntityActivityCampaigns';
import EntityActivityIncidents from './EntityActivityIncidents';
import EntityActivityReports from './EntityActivityReports';
import WidgetPopover from './WidgetPopover';

const ResponsiveGridLayout = WidthProvider(Responsive);

const styles = (theme) => ({
  container: {
    margin: '0 -20px 0 -20px',
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 215px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
  paper: {
    height: '100%',
    margin: 0,
    padding: 20,
    borderRadius: 6,
    display: 'relative',
  },
});

class DashboardComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { openConfig: false, currentWidget: {} };
  }

  saveManifest(manifest) {
    const JSONManifest = JSON.stringify(manifest);
    commitMutation({
      mutation: workspaceMutationFieldPatch,
      variables: {
        id: this.props.workspace.id,
        input: {
          key: 'manifest',
          value: Buffer.from(JSONManifest).toString('base64'),
        },
      },
    });
  }

  decodeManifest() {
    const { workspace } = this.props;
    let manifest = { widgets: {}, config: {} };
    if (workspace.manifest && workspace.manifest.length > 0) {
      manifest = JSON.parse(
        Buffer.from(workspace.manifest, 'base64').toString('ascii'),
      );
    }
    return manifest;
  }

  handleAddWidget(widgetManifest) {
    const manifest = this.decodeManifest();
    const newManifest = R.assoc(
      'widgets',
      R.assoc(
        widgetManifest.id,
        R.assoc(
          'layout',
          {
            i: widgetManifest.id,
            x: 0,
            y: 0,
            w: 4,
            h: 4,
            minW: 2,
            minH: 2,
          },
          widgetManifest,
        ),
        manifest.widgets,
      ),
      manifest,
    );
    this.saveManifest(newManifest);
  }

  handleDeleteWidget(widgetId) {
    const manifest = this.decodeManifest();
    const newManifest = R.assoc(
      'widgets',
      R.dissoc(widgetId, manifest.widgets),
      manifest,
    );
    this.saveManifest(newManifest);
  }

  handleDateChange(type, value) {
    // eslint-disable-next-line no-nested-ternary
    const newValue = value && value.target
      ? value.target.value
      : value
        ? parse(value).format()
        : null;
    const manifest = this.decodeManifest();
    let newManifest = R.assoc(
      'config',
      R.assoc(type, newValue === 'none' ? null : newValue, manifest.config),
      manifest,
    );
    if (type === 'relativeDate' && newValue !== 'none') {
      newManifest = R.assoc(
        'config',
        R.assoc('startDate', null, newManifest.config),
        newManifest,
      );
      newManifest = R.assoc(
        'config',
        R.assoc('endDate', null, newManifest.config),
        newManifest,
      );
    }
    this.saveManifest(newManifest);
  }

  onLayoutChange(layouts) {
    const manifest = this.decodeManifest();
    const layoutsObject = R.indexBy(R.prop('i'), layouts);
    const newManifest = R.assoc(
      'widgets',
      R.map((n) => R.assoc('layout', layoutsObject[n.id], n), manifest.widgets),
      manifest,
    );
    this.saveManifest(newManifest);
  }

  // eslint-disable-next-line class-methods-use-this
  renderThreatVisualization(widget, config) {
    const { relativeDate } = config;
    const startDate = relativeDate
      ? this.computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? now() : config.endDate;
    switch (widget.dataType) {
      case 'all':
        return (
          <ThreatVictimologyAll
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'sectors':
        return (
          <ThreatVictimologySectors
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'countries':
        return (
          <ThreatVictimologyCountries
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'campaigns':
        return (
          <ThreatActivityCampaigns
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'indicators':
        return (
          <ThreatActivityIndicators
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'reports':
        return (
          <ThreatActivityReports
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      default:
        return 'Go away!';
    }
  }

  // eslint-disable-next-line class-methods-use-this
  computerRelativeDate(relativeDate) {
    if (relativeDate.includes('days')) {
      return daysAgo(relativeDate.split('-')[1]);
    }
    if (relativeDate.includes('months')) {
      return monthsAgo(relativeDate.split('-')[1]);
    }
    if (relativeDate.includes('years')) {
      return yearsAgo(relativeDate.split('-')[1]);
    }
    return null;
  }

  // eslint-disable-next-line class-methods-use-this
  renderEntityVisualization(widget, config) {
    const { relativeDate } = config;
    const startDate = relativeDate
      ? this.computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? now() : config.endDate;
    switch (widget.dataType) {
      case 'all':
        return (
          <EntityThreatsAll
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'intrusion-sets':
        return (
          <EntityThreatsIntrusionSets
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'malwares':
        return (
          <EntityThreatsMalwares
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'campaigns':
        return (
          <EntityActivityCampaigns
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'indidents':
        return (
          <EntityActivityIncidents
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'reports':
        return (
          <EntityActivityReports
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      default:
        return 'Go away!';
    }
  }

  render() {
    const { t, classes, workspace } = this.props;
    const manifest = this.decodeManifest();
    const relativeDate = R.propOr(null, 'relativeDate', manifest.config);
    return (
      <div className={classes.container}>
        <WorkspaceHeader workspace={workspace} />
        <Drawer
          anchor="bottom"
          variant="permanent"
          classes={{ paper: classes.bottomNav }}
        >
          <Grid container={true} spacing={1}>
            <Grid item={true} xs="auto">
              <FormControl style={{ width: 194, marginRight: 20 }}>
                <InputLabel id="relative">{t('Relative time')}</InputLabel>
                <Select
                  labelId="relative"
                  value={relativeDate}
                  onChange={this.handleDateChange.bind(this, 'relativeDate')}
                >
                  <MenuItem value="none">{t('None')}</MenuItem>
                  <MenuItem value="days-7">{t('Last 7 days')}</MenuItem>
                  <MenuItem value="months-12">{t('Last 12 months')}</MenuItem>
                  <MenuItem value="years-5">{t('Last 2 years')}</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item={true} xs="auto">
              <DatePicker
                value={R.propOr(null, 'startDate', manifest.config)}
                disableToolbar={true}
                format="YYYY-MM-DD"
                autoOk={true}
                label={t('Start date')}
                clearable={true}
                disableFuture={true}
                disabled={relativeDate !== null}
                onChange={this.handleDateChange.bind(this, 'startDate')}
                style={{ marginRight: 20 }}
              />
            </Grid>
            <Grid item={true} xs="auto">
              <DatePicker
                value={R.propOr(null, 'endDate', manifest.config)}
                disableToolbar={true}
                format="YYYY-MM-DD"
                autoOk={true}
                label={t('End date')}
                clearable={true}
                disabled={relativeDate !== null}
                disableFuture={true}
                onChange={this.handleDateChange.bind(this, 'endDate')}
              />
            </Grid>
          </Grid>
        </Drawer>
        <br />
        <ResponsiveGridLayout
          className="layout"
          margin={[20, 20]}
          breakpoints={{
            lg: 1200,
            md: 996,
            sm: 768,
            xs: 480,
            xxs: 0,
          }}
          cols={{
            lg: 12,
            md: 10,
            sm: 6,
            xs: 4,
            xxs: 2,
          }}
          onLayoutChange={this.onLayoutChange.bind(this)}
        >
          {R.values(manifest.widgets).map((widget) => (
            <Paper
              key={widget.id}
              data-grid={widget.layout}
              classes={{ root: classes.paper }}
              elevation={2}
            >
              <WidgetPopover
                onDelete={this.handleDeleteWidget.bind(this, widget.id)}
              />
              {widget.perspective === 'threat'
                ? this.renderThreatVisualization(widget, manifest.config)
                : this.renderEntityVisualization(widget, manifest.config)}
            </Paper>
          ))}
        </ResponsiveGridLayout>
        <Security needs={[EXPLORE_EXUPDATE]}>
          <WidgetCreation onComplete={this.handleAddWidget.bind(this)} />
        </Security>
      </div>
    );
  }
}

DashboardComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Dashboard = createFragmentContainer(DashboardComponent, {
  workspace: graphql`
    fragment Dashboard_workspace on Workspace {
      id
      identifier
      name
      description
      manifest
      tags
      owner {
        id
        name
      }
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(Dashboard);
