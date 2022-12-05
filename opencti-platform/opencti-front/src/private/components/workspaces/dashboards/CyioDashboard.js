import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { Responsive, WidthProvider } from 'react-grid-layout';
import { DatePicker } from '@material-ui/pickers';
import Grid from '@material-ui/core/Grid';
import InputLabel from '@material-ui/core/InputLabel';
import MenuItem from '@material-ui/core/MenuItem';
import FormControl from '@material-ui/core/FormControl';
import Select from '@material-ui/core/Select';
import Dialog from '@material-ui/core/Dialog';
import Slide from '@material-ui/core/Slide';
import DialogContent from '@material-ui/core/DialogContent';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import {
  daysAgo,
  monthsAgo,
  parse,
  yearsAgo,
  dayStartDate,
} from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import CyioWorkspaceHeader from '../CyioWorkspaceHeader';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import CyioWidgetCreation from './CyioWidgetCreation';
import CyioWidgetPopover from './CyioWidgetPopover';
import { toastGenericError } from '../../../../utils/bakedToast';
import Loader from '../../../../components/Loader';
import CyioCoreObjectWidgetAreaChart from '../widgets/CyioCoreObjectWidgetAreaChart';
import CyioCoreObjectWidgetCount from '../widgets/CyioCoreObjectWidgetCount';
import CyioCoreObjectWidgetDonutChart from '../widgets/CyioCoreObjectWidgetDonutChart';
import CyioCoreObjectWidgetHorizontalBars from '../widgets/CyioCoreObjectWidgetHorizontalBars';
import CyioCoreObjectWidgetLineChart from '../widgets/CyioCoreObjectWidgetLineChart';
import CyioCoreObjectWidgetVerticalBars from '../widgets/CyioCoreObjectWidgetVerticalBars';
import CyioCoreObjectWidgetListChart from '../widgets/CyioCoreObjectWidgetListChart';

const ResponsiveGridLayout = WidthProvider(Responsive);

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  bottomNav: {
    padding: '17px 50px',
    zIndex: '1',
    overflow: 'hidden',
    backgroundColor: theme.palette.navBottom.background,
    position: 'fixed',
    width: '100%',
    bottom: '0',
    marginLeft: '-30px',
  },
  paper: {
    height: '100%',
    margin: 0,
    padding: 20,
    borderRadius: 6,
    display: 'relative',
  },
  dialogContent: {
    overflow: 'hidden',
    height: '300px',
  },
});

const cyioDashboardWizardQuery = graphql`
  query CyioDashboardWizardQuery {
    workspaceWizardConfig
  }
`;

class DashboardComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openConfig: false,
      currentWidget: {},
      mapReload: false,
      openWidgetCreate: false,
      wizardConfig: {},
    };
  }

  saveManifest(manifest) {
    const { workspace } = this.props;
    const newManifest = Buffer.from(JSON.stringify(manifest)).toString(
      'base64',
    );
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

  handleWidgetCreation() {
    this.setState({ openWidgetCreate: !this.state.openWidgetCreate });
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

  static getDayStartDate() {
    return dayStartDate(null, false);
  }

  // eslint-disable-next-line class-methods-use-this
  renderVisualization(widget, config) {
    const { t } = this.props;
    const { relativeDate } = config;
    const startDate = relativeDate
      ? this.computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate
      ? DashboardComponent.getDayStartDate()
      : config.endDate;
    switch (widget.visualizationType) {
      case 'area':
        return (
          <CyioCoreObjectWidgetAreaChart
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'count':
        return (
          <CyioCoreObjectWidgetCount
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'donut':
        return (
          <CyioCoreObjectWidgetDonutChart
            startDate={startDate}
            endDate={endDate}
            widget={widget}
            mapReload={this.state.mapReload}
          />
        );
      case 'horizontal-bar':
        return (
          <CyioCoreObjectWidgetHorizontalBars
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'line':
        return (
          <CyioCoreObjectWidgetLineChart
            startDate={startDate}
            endDate={endDate}
            widget={widget}
            mapReload={this.state.mapReload}
          />
        );
      case 'vertical-bar':
        return (
          <CyioCoreObjectWidgetVerticalBars
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      case 'list':
        return (
          <CyioCoreObjectWidgetListChart
            startDate={startDate}
            endDate={endDate}
            widget={widget}
          />
        );
      // case 'map':
      //   return (
      //     <GlobalVictimologyCountries
      //       startDate={startDate}
      //       endDate={endDate}
      //       widget={widget}
      //       mapReload={this.state.mapReload}
      //     />
      //   );
      // case 'timeline':
      //   return (
      //     <GlobalVictimologyCountries
      //       startDate={startDate}
      //       endDate={endDate}
      //       widget={widget}
      //       mapReload={this.state.mapReload}
      //     />
      //   );
      default:
        return (
          <div style={{ display: 'table', height: '100%', width: '100%' }}>
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t('Not implemented yet.')}
            </span>
          </div>
        );
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

  render() {
    const {
      t, classes, workspace, history, noToolbar,
    } = this.props;
    const manifest = this.decodeManifest();
    const relativeDate = R.propOr(null, 'relativeDate', manifest.config);
    return (
      <div className={classes.container} id="container">
        {!noToolbar && (
          <CyioWorkspaceHeader
            history={history}
            workspace={workspace}
            variant="dashboard"
            handleWidgetCreation={this.handleWidgetCreation.bind(this)}
          />
        )}
        {!noToolbar && (
          <div className={classes.bottomNav}>
            {/* <Security
              needs={[EXPLORE_EXUPDATE]}
              placeholder={
                <Grid container={true} spacing={1}>
                  <Grid item={true} xs="auto">
                    <FormControl style={{ width: 194, marginRight: 20 }}>
                      <InputLabel id="relative">{t('Relative time')}</InputLabel>
                      <Select
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
                        <MenuItem value="months-6">{t('Last 6 months')}</MenuItem>
                        <MenuItem value="years-1">{t('Last year')}</MenuItem>
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
                      disabled={true}
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
                      disabled={true}
                      disableFuture={true}
                      onChange={this.handleDateChange.bind(this, 'endDate')}
                    />
                  </Grid>
                </Grid>
              }
            > */}
            <Grid container={true} spacing={1}>
              <Grid item={true} xs="auto">
                <FormControl style={{ width: 194, marginRight: 20 }}>
                  <InputLabel id="relative">{t('Relative time')}</InputLabel>
                  <Select
                    labelId="relative"
                    value={relativeDate === null ? '' : relativeDate}
                    onChange={this.handleDateChange.bind(this, 'relativeDate')}
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
            {/* </Security> */}
          </div>
        )}
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
            lg: 18,
            md: 18,
            sm: 18,
            xs: 18,
            xxs: 18,
          }}
          isDraggable={!noToolbar}
          isResizable={!noToolbar}
          onLayoutChange={this.onLayoutChange.bind(this)}
        >
          {R.values(manifest.widgets).map((widget) => (
            <Paper
              key={widget.id}
              data-grid={widget.layout}
              classes={{ root: classes.paper }}
              elevation={2}
            >
              {!noToolbar && (
                <CyioWidgetPopover
                  onDelete={this.handleDeleteWidget.bind(this, widget.id)}
                />
              )}
              {widget.perspective && this.renderVisualization(widget, manifest.config)}
            </Paper>
          ))}
        </ResponsiveGridLayout>
        <Dialog
          open={this.state.openWidgetCreate}
          TransitionComponent={Transition}
          fullWidth={true}
          maxWidth="md"
        >
          <QueryRenderer
            query={cyioDashboardWizardQuery}
            render={({ error, props }) => {
              if (error) {
                toastGenericError('Request Failed');
              }
              if (props) {
                const propsWizard = JSON.parse(Buffer.from(props.workspaceWizardConfig, 'base64').toString('ascii'));
                return (
                  <CyioWidgetCreation
                    open={this.state.openWidgetCreate}
                    wizardConfig={propsWizard.wizardConfig}
                    handleWidgetCreation={this.handleWidgetCreation.bind(this)}
                    onComplete={this.handleAddWidget.bind(this)}
                  />
                );
              }
              return (
                <DialogContent classes={{ root: classes.dialogContent }}>
                  <Loader />
                </DialogContent>
              );
            }}
          />
        </Dialog>
      </div>
    );
  }
}

DashboardComponent.propTypes = {
  noToolbar: PropTypes.bool,
  workspace: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const Dashboard = createFragmentContainer(DashboardComponent, {
  workspace: graphql`
    fragment CyioDashboard_workspace on Workspace {
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
