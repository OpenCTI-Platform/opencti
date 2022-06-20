import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import { Responsive, WidthProvider } from 'react-grid-layout';
import { DatePicker } from '@mui/x-date-pickers/DatePicker';
import Drawer from '@mui/material/Drawer';
import Grid from '@mui/material/Grid';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import FormControl from '@mui/material/FormControl';
import Select from '@mui/material/Select';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import TextField from '@mui/material/TextField';
import {
  daysAgo,
  monthsAgo,
  parse,
  yearsAgo,
  dayStartDate,
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
import ThreatVictimologyRegions from './ThreatVictimologyRegions';
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
import GlobalVictimologyAll from './GlobalVictimologyAll';
import GlobalVictimologySectors from './GlobalVictimologySectors';
import GlobalVictimologyCountries from './GlobalVictimologyCountries';
import GlobalVictimologyRegions from './GlobalVictimologyRegions';
import GlobalActivityIntrusionSets from './GlobalActivityIntrusionSets';
import GlobalActivityMalwares from './GlobalActivityMalwares';
import GlobalActivityReports from './GlobalActivityReports';
import GlobalActivityIndicators from './GlobalActivityIndicators';
import GlobalActivityVulnerabilities from './GlobalActivityVulnerabilities';
import ThreatVulnerabilities from './ThreatVulnerabilities';
import { fromB64, toB64 } from '../../../../utils/String';
import GlobalActivityStixCoreRelationships from './GlobalActivityStixCoreRelationships';

const ResponsiveGridLayout = WidthProvider(Responsive);

const styles = () => ({
  container: {
    margin: '0 -20px 0 -20px',
  },
  bottomNav: {
    zIndex: 1000,
    padding: '7px 0 0 205px',
    display: 'flex',
    height: 64,
    overflow: 'hidden',
  },
  paper: {
    height: '100%',
    margin: 0,
    padding: 20,
    borderRadius: 6,
    display: 'relative',
    overflow: 'hidden',
  },
});

class DashboardComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { openConfig: false, currentWidget: {}, mapReload: false };
  }

  saveManifest(manifest) {
    const { workspace } = this.props;
    const newManifest = toB64(JSON.stringify(manifest));
    if (workspace.manifest !== newManifest) {
      commitMutation({
        mutation: workspaceMutationFieldPatch,
        variables: {
          id: this.props.workspace.id,
          input: {
            key: 'manifest',
            value: newManifest,
          },
        },
      });
    }
  }

  decodeManifest() {
    const { workspace } = this.props;
    let manifest = { widgets: {}, config: {} };
    if (workspace.manifest && workspace.manifest.length > 0) {
      manifest = JSON.parse(fromB64(workspace.manifest));
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
            h: 2,
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

  handleTimeFieldChange(event) {
    const newValue = event.target.value;
    const manifest = this.decodeManifest();
    const newManifest = R.assoc(
      'config',
      R.assoc(
        'timeField',
        newValue === 'none' ? null : newValue,
        manifest.config,
      ),
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
    this.setState({ mapReload: true }, () => this.setState({ mapReload: false }));
    this.saveManifest(newManifest);
  }

  onConfigChange(config) {
    const manifest = this.decodeManifest();
    const newManifest = R.assoc(
      'widgets',
      R.map((n) => R.assoc('config', config, n), manifest.widgets),
      manifest,
    );
    this.setState({ mapReload: true }, () => this.setState({ mapReload: false }));
    this.saveManifest(newManifest);
  }

  static getDayStartDate() {
    return dayStartDate(null, false);
  }

  // eslint-disable-next-line class-methods-use-this
  renderGlobalVisualization(widget, config) {
    const { relativeDate } = config;
    let { timeField = 'technical' } = config;
    if (this.props.timeField) {
      timeField = this.props.timeField;
    }
    const startDate = relativeDate
      ? this.computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate
      ? DashboardComponent.getDayStartDate()
      : config.endDate;
    switch (widget.dataType) {
      case 'all':
        return (
          <GlobalVictimologyAll
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'sectors':
        return (
          <GlobalVictimologySectors
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'regions':
        return (
          <GlobalVictimologyRegions
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
            mapReload={this.state.mapReload}
          />
        );
      case 'countries':
        return (
          <GlobalVictimologyCountries
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
            mapReload={this.state.mapReload}
          />
        );
      case 'intrusion-sets':
        return (
          <GlobalActivityIntrusionSets
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'malwares':
        return (
          <GlobalActivityMalwares
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'vulnerabilities':
        return (
          <GlobalActivityVulnerabilities
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'reports':
        return (
          <GlobalActivityReports
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
            onConfigChange={this.onConfigChange.bind(this)}
          />
        );
      case 'indicators':
        return (
          <GlobalActivityIndicators
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'indicators_lifecycle':
        return (
          <GlobalActivityIndicators
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
            field="revoked"
          />
        );
      case 'indicators_detection':
        return (
          <GlobalActivityIndicators
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
            field="x_opencti_detection"
          />
        );
      case 'relationships_list':
        return (
          <GlobalActivityStixCoreRelationships
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
            onConfigChange={this.onConfigChange.bind(this)}
          />
        );
      default:
        return 'Go away!';
    }
  }

  // eslint-disable-next-line class-methods-use-this
  renderThreatVisualization(widget, config) {
    const { relativeDate } = config;
    let { timeField = 'technical' } = config;
    if (this.props.timeField) {
      timeField = this.props.timeField;
    }
    const startDate = relativeDate
      ? this.computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate
      ? DashboardComponent.getDayStartDate()
      : config.endDate;
    switch (widget.dataType) {
      case 'all':
        return (
          <ThreatVictimologyAll
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'sectors':
        return (
          <ThreatVictimologySectors
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'regions':
        return (
          <ThreatVictimologyRegions
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
            mapReload={this.state.mapReload}
          />
        );
      case 'countries':
        return (
          <ThreatVictimologyCountries
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
            mapReload={this.state.mapReload}
          />
        );
      case 'campaigns':
        return (
          <ThreatActivityCampaigns
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'indicators':
        return (
          <ThreatActivityIndicators
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'vulnerabilities':
        return (
          <ThreatVulnerabilities
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'reports':
        return (
          <ThreatActivityReports
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
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
      return daysAgo(relativeDate.split('-')[1], null, false);
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
    let { timeField = 'technical' } = config;
    if (this.props.timeField) {
      timeField = this.props.timeField;
    }
    const startDate = relativeDate
      ? this.computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate
      ? DashboardComponent.getDayStartDate()
      : config.endDate;
    switch (widget.dataType) {
      case 'all':
        return (
          <EntityThreatsAll
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'intrusion-sets':
        return (
          <EntityThreatsIntrusionSets
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'malwares':
        return (
          <EntityThreatsMalwares
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'campaigns':
        return (
          <EntityActivityCampaigns
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'incidents':
        return (
          <EntityActivityIncidents
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      case 'reports':
        return (
          <EntityActivityReports
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
          />
        );
      default:
        return 'Go away!';
    }
  }

  render() {
    const { t, classes, workspace, noToolbar } = this.props;
    const manifest = this.decodeManifest();
    const relativeDate = R.propOr(null, 'relativeDate', manifest.config);
    let timeField = R.propOr('technical', 'timeField', manifest.config);
    if (this.props.timeField) {
      timeField = this.props.timeField;
    }
    return (
      <div
        className={classes.container}
        id="container"
        style={{
          paddingBottom: noToolbar ? 0 : 50,
          marginTop: noToolbar ? -20 : 0,
        }}
      >
        {!noToolbar && (
          <WorkspaceHeader workspace={workspace} variant="dashboard" />
        )}
        {!noToolbar && (
          <Drawer
            anchor="bottom"
            variant="permanent"
            classes={{ paper: classes.bottomNav }}
            PaperProps={{ variant: 'elevation', elevation: 1 }}
          >
            <Security
              needs={[EXPLORE_EXUPDATE]}
              placeholder={
                <Grid container={true} spacing={1}>
                  <Grid item={true} xs="auto">
                    <FormControl style={{ width: 194, marginRight: 20 }}>
                      <InputLabel id="timeField" variant="standard">
                        {t('Date reference')}
                      </InputLabel>
                      <Select
                        variant="standard"
                        labelId="timeField"
                        value={timeField === null ? '' : timeField}
                        onChange={this.handleTimeFieldChange.bind(this)}
                        disabled={true}
                      >
                        <MenuItem value="technical">
                          {t('Technical date')}
                        </MenuItem>
                        <MenuItem value="functional">
                          {t('Functional date')}
                        </MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item={true} xs="auto">
                    <FormControl style={{ width: 194, marginRight: 20 }}>
                      <InputLabel id="relative" variant="standard">
                        {t('Relative time')}
                      </InputLabel>
                      <Select
                        variant="standard"
                        labelId="relative"
                        value={relativeDate === null ? '' : relativeDate}
                        onChange={this.handleDateChange.bind(
                          this,
                          'relativeDate',
                        )}
                        disabled={true}
                      >
                        <MenuItem value="none">{t('None')}</MenuItem>
                        <MenuItem value="days-1">{t('Last 24 hours')}</MenuItem>
                        <MenuItem value="days-7">{t('Last 7 days')}</MenuItem>
                        <MenuItem value="months-1">{t('Last month')}</MenuItem>
                        <MenuItem value="months-6">
                          {t('Last 6 months')}
                        </MenuItem>
                        <MenuItem value="years-1">{t('Last year')}</MenuItem>
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item={true} xs="auto">
                    <DatePicker
                      value={R.propOr(null, 'startDate', manifest.config)}
                      disableToolbar={true}
                      autoOk={true}
                      label={t('Start date')}
                      clearable={true}
                      disableFuture={true}
                      disabled={true}
                      onChange={this.handleDateChange.bind(this, 'startDate')}
                      renderInput={(params) => (
                        <TextField
                          style={{ marginRight: 20 }}
                          variant="standard"
                          size="small"
                          {...params}
                        />
                      )}
                    />
                  </Grid>
                  <Grid item={true} xs="auto">
                    <DatePicker
                      value={R.propOr(null, 'endDate', manifest.config)}
                      disableToolbar={true}
                      autoOk={true}
                      label={t('End date')}
                      clearable={true}
                      disabled={true}
                      disableFuture={true}
                      onChange={this.handleDateChange.bind(this, 'endDate')}
                      renderInput={(params) => (
                        <TextField
                          style={{ marginRight: 20 }}
                          variant="standard"
                          size="small"
                          {...params}
                        />
                      )}
                    />
                  </Grid>
                </Grid>
              }
            >
              <Grid container={true} spacing={1}>
                <Grid item={true} xs="auto">
                  <FormControl style={{ width: 194, marginRight: 20 }}>
                    <InputLabel id="timeField" variant="standard">
                      {t('Date reference')}
                    </InputLabel>
                    <Select
                      variant="standard"
                      labelId="timeField"
                      size="small"
                      value={timeField === null ? '' : timeField}
                      onChange={this.handleTimeFieldChange.bind(this)}
                    >
                      <MenuItem value="technical">
                        {t('Technical date')}
                      </MenuItem>
                      <MenuItem value="functional">
                        {t('Functional date')}
                      </MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item={true} xs="auto">
                  <FormControl style={{ width: 194, marginRight: 20 }}>
                    <InputLabel id="relative" variant="standard">
                      {t('Relative time')}
                    </InputLabel>
                    <Select
                      variant="standard"
                      labelId="relative"
                      size="small"
                      value={relativeDate === null ? '' : relativeDate}
                      onChange={this.handleDateChange.bind(
                        this,
                        'relativeDate',
                      )}
                    >
                      <MenuItem value="none">{t('None')}</MenuItem>
                      <MenuItem value="days-1">{t('Last 24 hours')}</MenuItem>
                      <MenuItem value="days-7">{t('Last 7 days')}</MenuItem>
                      <MenuItem value="months-1">{t('Last month')}</MenuItem>
                      <MenuItem value="months-6">{t('Last 6 months')}</MenuItem>
                      <MenuItem value="years-1">{t('Last year')}</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item={true} xs="auto">
                  <DatePicker
                    value={R.propOr(null, 'startDate', manifest.config)}
                    disableToolbar={true}
                    autoOk={true}
                    label={t('Start date')}
                    clearable={true}
                    disableFuture={true}
                    disabled={relativeDate !== null}
                    onChange={this.handleDateChange.bind(this, 'startDate')}
                    renderInput={(params) => (
                      <TextField
                        style={{ marginRight: 20 }}
                        variant="standard"
                        size="small"
                        {...params}
                      />
                    )}
                  />
                </Grid>
                <Grid item={true} xs="auto">
                  <DatePicker
                    value={R.propOr(null, 'endDate', manifest.config)}
                    autoOk={true}
                    label={t('End date')}
                    clearable={true}
                    disabled={relativeDate !== null}
                    disableFuture={true}
                    onChange={this.handleDateChange.bind(this, 'endDate')}
                    renderInput={(params) => (
                      <TextField variant="standard" size="small" {...params} />
                    )}
                  />
                </Grid>
              </Grid>
            </Security>
          </Drawer>
        )}
        <Security
          needs={[EXPLORE_EXUPDATE]}
          placeholder={
            <ResponsiveGridLayout
              className="layout"
              margin={[20, 20]}
              rowHeight={50}
              breakpoints={{
                lg: 1200,
                md: 1200,
                sm: 1200,
                xs: 1200,
                xxs: 1200,
              }}
              cols={{
                lg: 30,
                md: 30,
                sm: 30,
                xs: 30,
                xxs: 30,
              }}
              isDraggable={false}
              isResizable={false}
            >
              {R.values(manifest.widgets).map((widget) => (
                <Paper
                  key={widget.id}
                  data-grid={widget.layout}
                  classes={{ root: classes.paper }}
                  variant="outlined"
                >
                  {widget.perspective === 'global'
                    && this.renderGlobalVisualization(widget, manifest.config)}
                  {widget.perspective === 'threat'
                    && this.renderThreatVisualization(widget, manifest.config)}
                  {widget.perspective === 'entity'
                    && this.renderEntityVisualization(widget, manifest.config)}
                </Paper>
              ))}
            </ResponsiveGridLayout>
          }
        >
          <ResponsiveGridLayout
            className="layout"
            margin={[20, 20]}
            rowHeight={50}
            breakpoints={{
              lg: 1200,
              md: 1200,
              sm: 1200,
              xs: 1200,
              xxs: 1200,
            }}
            cols={{
              lg: 30,
              md: 30,
              sm: 30,
              xs: 30,
              xxs: 30,
            }}
            isDraggable={!noToolbar}
            isResizable={!noToolbar}
            onLayoutChange={
              noToolbar ? () => true : this.onLayoutChange.bind(this)
            }
          >
            {R.values(manifest.widgets).map((widget) => (
              <Paper
                key={widget.id}
                data-grid={widget.layout}
                classes={{ root: classes.paper }}
                variant="outlined"
              >
                {!noToolbar && (
                  <WidgetPopover
                    onDelete={this.handleDeleteWidget.bind(this, widget.id)}
                  />
                )}
                {widget.perspective === 'global'
                  && this.renderGlobalVisualization(widget, manifest.config)}
                {widget.perspective === 'threat'
                  && this.renderThreatVisualization(widget, manifest.config)}
                {widget.perspective === 'entity'
                  && this.renderEntityVisualization(widget, manifest.config)}
              </Paper>
            ))}
          </ResponsiveGridLayout>
          {!noToolbar && (
            <WidgetCreation onComplete={this.handleAddWidget.bind(this)} />
          )}
        </Security>
      </div>
    );
  }
}

DashboardComponent.propTypes = {
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  noToolbar: PropTypes.bool,
  timeField: PropTypes.string,
};

const Dashboard = createFragmentContainer(DashboardComponent, {
  workspace: graphql`
    fragment Dashboard_workspace on Workspace {
      id
      type
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
