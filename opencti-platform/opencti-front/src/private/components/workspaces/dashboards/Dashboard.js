import React, { useState } from 'react';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import { Responsive, WidthProvider } from 'react-grid-layout';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import {
  daysAgo,
  monthsAgo,
  yearsAgo,
  dayStartDate,
  parse,
} from '../../../../utils/Time';
import WorkspaceHeader from '../WorkspaceHeader';
import { commitMutation } from '../../../../relay/environment';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
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
import WidgetConfig from './WidgetConfig';
import StixCoreObjectsMultiVerticalBars from '../../common/stix_core_objects/StixCoreObjectsMultiVerticalBars';
import StixCoreObjectsNumber from '../../common/stix_core_objects/StixCoreObjectsNumber';
import StixCoreObjectsList from '../../common/stix_core_objects/StixCoreObjectsList';
import StixCoreObjectsMultiLineChart from '../../common/stix_core_objects/StixCoreObjectsMultiLineChart';
import StixCoreObjectsMultiAreaChart from '../../common/stix_core_objects/StixCoreObjectsMultiAreaChart';
import StixCoreObjectsTimeline from '../../common/stix_core_objects/StixCoreObjectsTimeline';
import StixCoreObjectsDonut from '../../common/stix_core_objects/StixCoreObjectsDonut';
import StixCoreRelationshipsHorizontalBars from '../../common/stix_core_relationships/StixCoreRelationshipsHorizontalBars';
import StixCoreRelationshipsMultiVerticalBars from '../../common/stix_core_relationships/StixCoreRelationshipsMultiVerticalBars';
import StixCoreObjectsHorizontalBars from '../../common/stix_core_objects/StixCoreObjectsHorizontalBars';
import StixCoreRelationshipsMultiHorizontalBars from '../../common/stix_core_relationships/StixCoreRelationshipsMultiHorizontalBars';
import StixCoreObjectsRadar from '../../common/stix_core_objects/StixCoreObjectsRadar';
import StixCoreRelationshipsList from '../../common/stix_core_relationships/StixCoreRelationshipsList';
import StixCoreRelationshipsNumber from '../../common/stix_core_relationships/StixCoreRelationshipsNumber';
import StixCoreRelationshipsMultiLineChart from '../../common/stix_core_relationships/StixCoreRelationshipsMultiLineChart';
import StixCoreRelationshipsMultiAreaChart from '../../common/stix_core_relationships/StixCoreRelationshipsMultiAreaChart';

const ResponsiveGridLayout = WidthProvider(Responsive);

const useStyles = makeStyles(() => ({
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
}));

const DashboardComponent = ({ workspace, noToolbar }) => {
  const classes = useStyles();
  const [manifest, setManifest] = useState(
    workspace.manifest && workspace.manifest.length > 0
      ? JSON.parse(fromB64(workspace.manifest))
      : { widgets: {}, config: {} },
  );
  const [deleting, setDeleting] = useState(false);
  const saveManifest = (newManifest) => {
    setManifest(newManifest);
    const newManifestEncoded = toB64(JSON.stringify(newManifest));
    if (workspace.manifest !== newManifestEncoded) {
      commitMutation({
        mutation: workspaceMutationFieldPatch,
        variables: {
          id: workspace.id,
          input: {
            key: 'manifest',
            value: newManifestEncoded,
          },
        },
      });
    }
  };
  const handleDateChange = (type, value) => {
    // eslint-disable-next-line no-nested-ternary
    const newValue = value && value.target
      ? value.target.value
      : value
        ? parse(value).format()
        : null;
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
    saveManifest(newManifest);
  };
  const handleAddWidget = (widgetManifest) => {
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
    saveManifest(newManifest);
  };
  const handleUpdateWidget = (widgetManifest) => {
    const newManifest = R.assoc(
      'widgets',
      R.assoc(widgetManifest.id, widgetManifest, manifest.widgets),
      manifest,
    );
    saveManifest(newManifest);
  };
  const handleDeleteWidget = (widgetId) => {
    setDeleting(true);
    const newManifest = R.assoc(
      'widgets',
      R.dissoc(widgetId, manifest.widgets),
      manifest,
    );
    saveManifest(newManifest);
  };
  const onLayoutChange = (layouts) => {
    if (!deleting) {
      const layoutsObject = R.indexBy(R.prop('i'), layouts);
      const newManifest = R.assoc(
        'widgets',
        R.map(
          (n) => R.assoc('layout', layoutsObject[n.id], n),
          manifest.widgets,
        ),
        manifest,
      );
      saveManifest(newManifest);
    }
  };
  const onConfigChange = (config) => {
    const newManifest = R.assoc(
      'widgets',
      R.map((n) => R.assoc('config', config, n), manifest.widgets),
      manifest,
    );
    saveManifest(newManifest);
  };
  const getDayStartDate = () => {
    return dayStartDate(null, false);
  };
  const computerRelativeDate = (relativeDate) => {
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
  };
  const renderGlobalVisualization = (widget, config) => {
    const { relativeDate } = config;
    const { timeField = 'technical' } = config;
    const startDate = relativeDate
      ? computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? getDayStartDate() : config.endDate;
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
          />
        );
      case 'countries':
        return (
          <GlobalVictimologyCountries
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
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
            onConfigChange={onConfigChange}
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
            onConfigChange={onConfigChange}
          />
        );
      default:
        return 'Go away!';
    }
  };
  const renderThreatVisualization = (widget, config) => {
    const { relativeDate } = config;
    const { timeField = 'technical' } = config;
    const startDate = relativeDate
      ? computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? getDayStartDate() : config.endDate;
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
          />
        );
      case 'countries':
        return (
          <ThreatVictimologyCountries
            startDate={startDate}
            endDate={endDate}
            timeField={timeField}
            widget={widget}
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
  };
  const renderEntityVisualization = (widget, config) => {
    const { relativeDate } = config;
    const { timeField = 'technical' } = config;
    const startDate = relativeDate
      ? computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? getDayStartDate() : config.endDate;
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
  };
  const renderEntitiesVisualization = (widget, config) => {
    const { relativeDate } = config;
    const startDate = relativeDate
      ? computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? getDayStartDate() : config.endDate;
    switch (widget.type) {
      case 'number':
        return (
          <StixCoreObjectsNumber
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <StixCoreObjectsList
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <StixCoreObjectsMultiVerticalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'line':
        return (
          <StixCoreObjectsMultiLineChart
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'area':
        return (
          <StixCoreObjectsMultiAreaChart
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'timeline':
        return (
          <StixCoreObjectsTimeline
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <StixCoreObjectsDonut
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'horizontal-bar':
        return (
          <StixCoreObjectsHorizontalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'radar':
        return (
          <StixCoreObjectsRadar
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      default:
        return 'Not implemented yet';
    }
  };
  const renderRelationshipsVisualization = (widget, config) => {
    const { relativeDate } = config;
    const startDate = relativeDate
      ? computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? getDayStartDate() : config.endDate;
    switch (widget.type) {
      case 'number':
        return (
          <StixCoreRelationshipsNumber
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <StixCoreRelationshipsList
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <StixCoreRelationshipsMultiVerticalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'line':
        return (
          <StixCoreRelationshipsMultiLineChart
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'area':
        return (
          <StixCoreRelationshipsMultiAreaChart
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'horizontal-bar':
        if (widget.dataSelection.length > 1) {
          return (
            <StixCoreRelationshipsMultiHorizontalBars
              startDate={startDate}
              endDate={endDate}
              dataSelection={widget.dataSelection}
              parameters={widget.parameters}
              variant="inLine"
            />
          );
        }
        return (
          <StixCoreRelationshipsHorizontalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      default:
        return 'Not implemented yet';
    }
  };
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
        <WorkspaceHeader
          workspace={workspace}
          config={manifest.config}
          handleDateChange={handleDateChange}
          variant="dashboard"
        />
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
                  && renderGlobalVisualization(widget, manifest.config)}
                {widget.perspective === 'threat'
                  && renderThreatVisualization(widget, manifest.config)}
                {widget.perspective === 'entity'
                  && renderEntityVisualization(widget, manifest.config)}
                {widget.perspective === 'entities'
                  && renderEntitiesVisualization(widget, manifest.config)}
                {widget.perspective === 'relationships'
                  && renderRelationshipsVisualization(widget, manifest.config)}
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
          onLayoutChange={noToolbar ? () => true : onLayoutChange}
          draggableCancel=".noDrag"
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
                  widget={widget}
                  onUpdate={handleUpdateWidget}
                  onDelete={() => handleDeleteWidget(widget.id)}
                />
              )}
              {widget.perspective === 'global'
                && renderGlobalVisualization(widget, manifest.config)}
              {widget.perspective === 'threat'
                && renderThreatVisualization(widget, manifest.config)}
              {widget.perspective === 'entity'
                && renderEntityVisualization(widget, manifest.config)}
              {widget.perspective === 'entities'
                && renderEntitiesVisualization(widget, manifest.config)}
              {widget.perspective === 'relationships'
                && renderRelationshipsVisualization(widget, manifest.config)}
            </Paper>
          ))}
        </ResponsiveGridLayout>
        {!noToolbar && <WidgetConfig onComplete={handleAddWidget} />}
      </Security>
    </div>
  );
};

export default createFragmentContainer(DashboardComponent, {
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
