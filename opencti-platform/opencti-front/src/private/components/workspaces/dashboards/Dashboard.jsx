import React, { useEffect, useState } from 'react';
import * as R from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import { Responsive, WidthProvider } from 'react-grid-layout';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { v4 as uuid } from 'uuid';
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
import Security from '../../../../utils/Security';
import useGranted, { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import WidgetPopover from './WidgetPopover';
import { fromB64, toB64 } from '../../../../utils/String';
import WidgetConfig from './WidgetConfig';
import StixCoreObjectsMultiVerticalBars from '../../common/stix_core_objects/StixCoreObjectsMultiVerticalBars';
import StixCoreObjectsNumber from '../../common/stix_core_objects/StixCoreObjectsNumber';
import StixCoreObjectsList from '../../common/stix_core_objects/StixCoreObjectsList';
import StixCoreObjectsDistributionList from '../../common/stix_core_objects/StixCoreObjectsDistributionList';
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
import StixCoreRelationshipsDistributionList from '../../common/stix_core_relationships/StixCoreRelationshipsDistributionList';
import StixCoreRelationshipsNumber from '../../common/stix_core_relationships/StixCoreRelationshipsNumber';
import StixCoreRelationshipsMultiLineChart from '../../common/stix_core_relationships/StixCoreRelationshipsMultiLineChart';
import StixCoreRelationshipsMultiAreaChart from '../../common/stix_core_relationships/StixCoreRelationshipsMultiAreaChart';
import StixCoreRelationshipsTimeline from '../../common/stix_core_relationships/StixCoreRelationshipsTimeline';
import StixCoreRelationshipsDonut from '../../common/stix_core_relationships/StixCoreRelationshipsDonut';
import StixCoreRelationshipsRadar from '../../common/stix_core_relationships/StixCoreRelationshipsRadar';
import StixCoreObjectsMultiHeatMap from '../../common/stix_core_objects/StixCoreObjectsMultiHeatMap';
import StixCoreRelationshipsMultiHeatMap from '../../common/stix_core_relationships/StixCoreRelationshipsMultiHeatMap';
import StixCoreObjectsTreeMap from '../../common/stix_core_objects/StixCoreObjectsTreeMap';
import StixCoreRelationshipsTreeMap from '../../common/stix_core_relationships/StixCoreRelationshipsTreeMap';
import StixCoreRelationshipsMap from '../../common/stix_core_relationships/StixCoreRelationshipsMap';
import StixDomainObjectBookmarksList from '../../common/stix_domain_objects/StixDomainObjectBookmarksList';
import StixCoreObjectsMultiHorizontalBars from '../../common/stix_core_objects/StixCoreObjectsMultiHorizontalBars';
import { ErrorBoundary, SimpleError } from '../../Error';
import { useFormatter } from '../../../../components/i18n';

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
  const { t } = useFormatter();
  const isExploreEditor = useGranted([EXPLORE_EXUPDATE]);
  const [manifest, setManifest] = useState(
    workspace.manifest && workspace.manifest.length > 0
      ? JSON.parse(fromB64(workspace.manifest))
      : { widgets: {}, config: {} },
  );
  useEffect(() => {
    setManifest(workspace.manifest && workspace.manifest.length > 0
      ? JSON.parse(fromB64(workspace.manifest))
      : { widgets: {}, config: {} });
  }, [workspace]);
  const [deleting, setDeleting] = useState(false);
  const userCanEdit = workspace.currentUserAccessRight === 'admin'
    || workspace.currentUserAccessRight === 'edit';
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
  const handleDuplicateWidget = (widgetManifest) => {
    const newId = uuid();
    const newManifest = R.assoc(
      'widgets',
      R.assoc(newId, R.assoc('id', newId, widgetManifest), manifest.widgets),
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
  const renderEntitiesVisualization = (widget, config) => {
    const { relativeDate } = config;
    const startDate = relativeDate
      ? computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? getDayStartDate() : config.endDate;
    switch (widget.type) {
      case 'bookmark':
        return (
          <StixDomainObjectBookmarksList
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
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
      case 'distribution-list':
        return (
          <StixCoreObjectsDistributionList
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
            withExportPopover={isExploreEditor}
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
            withExportPopover={isExploreEditor}
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
            withExportPopover={isExploreEditor}
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
            withExportPopover={isExploreEditor}
          />
        );
      case 'horizontal-bar':
        if (
          widget.dataSelection.length > 1
          && widget.dataSelection[0].attribute.endsWith('_id')
        ) {
          return (
            <StixCoreObjectsMultiHorizontalBars
              startDate={startDate}
              endDate={endDate}
              dataSelection={widget.dataSelection}
              parameters={widget.parameters}
              variant="inLine"
              withExportPopover={isExploreEditor}
            />
          );
        }
        return (
          <StixCoreObjectsHorizontalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={isExploreEditor}
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
            withExportPopover={isExploreEditor}
          />
        );
      case 'heatmap':
        return (
          <StixCoreObjectsMultiHeatMap
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={isExploreEditor}
          />
        );
      case 'tree':
        return (
          <StixCoreObjectsTreeMap
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={isExploreEditor}
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
      case 'distribution-list':
        return (
          <StixCoreRelationshipsDistributionList
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
            withExportPopover={isExploreEditor}
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
            withExportPopover={isExploreEditor}
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
            withExportPopover={isExploreEditor}
          />
        );
      case 'timeline':
        return (
          <StixCoreRelationshipsTimeline
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <StixCoreRelationshipsDonut
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={isExploreEditor}
          />
        );
      case 'horizontal-bar':
        if (
          widget.dataSelection.length > 1
          && widget.dataSelection[0].attribute === 'internal_id'
        ) {
          return (
            <StixCoreRelationshipsMultiHorizontalBars
              startDate={startDate}
              endDate={endDate}
              dataSelection={widget.dataSelection}
              parameters={widget.parameters}
              variant="inLine"
              withExportPopover={isExploreEditor}
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
            withExportPopover={isExploreEditor}
          />
        );
      case 'radar':
        return (
          <StixCoreRelationshipsRadar
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={isExploreEditor}
          />
        );
      case 'heatmap':
        return (
          <StixCoreRelationshipsMultiHeatMap
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={isExploreEditor}
          />
        );
      case 'tree':
        return (
          <StixCoreRelationshipsTreeMap
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={isExploreEditor}
          />
        );
      case 'map':
        return (
          <StixCoreRelationshipsMap
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
        hasAccess={userCanEdit}
        placeholder={
          <ResponsiveGridLayout
            className="layout"
            margin={[20, 20]}
            rowHeight={50}
            breakpoints={{ lg: 1200, md: 1200, sm: 1200, xs: 1200, xxs: 1200 }}
            cols={{ lg: 30, md: 30, sm: 30, xs: 30, xxs: 30 }}
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
                <ErrorBoundary
                  display={
                    <div style={{ paddingTop: 28 }}>
                      <SimpleError />
                    </div>
                  }
                >
                  {widget.perspective === 'entities'
                    && renderEntitiesVisualization(widget, manifest.config)}
                  {widget.perspective === 'relationships'
                    && renderRelationshipsVisualization(widget, manifest.config)}
                  {widget.perspective !== 'entities'
                    && widget.perspective !== 'relationships' && (
                      <div style={{ textAlign: 'center' }}>
                        <i>{t('Deprecated')}</i>
                      </div>
                  )}
                </ErrorBoundary>
              </Paper>
            ))}
          </ResponsiveGridLayout>
        }
      >
        <ResponsiveGridLayout
          className="layout"
          margin={[20, 20]}
          rowHeight={50}
          breakpoints={{ lg: 1200, md: 1200, sm: 1200, xs: 1200, xxs: 1200 }}
          cols={{ lg: 30, md: 30, sm: 30, xs: 30, xxs: 30 }}
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
                  onDuplicate={handleDuplicateWidget}
                  onDelete={() => handleDeleteWidget(widget.id)}
                />
              )}
              <ErrorBoundary
                display={
                  <div style={{ paddingTop: 28 }}>
                    <SimpleError />
                  </div>
                }
              >
                {widget.perspective === 'entities'
                  && renderEntitiesVisualization(widget, manifest.config)}
                {widget.perspective === 'relationships'
                  && renderRelationshipsVisualization(widget, manifest.config)}
                {widget.perspective !== 'entities'
                  && widget.perspective !== 'relationships' && (
                    <div style={{ textAlign: 'center' }}>
                      <i>{t('Deprecated')}</i>
                    </div>
                )}
              </ErrorBoundary>
            </Paper>
          ))}
        </ResponsiveGridLayout>
        {!noToolbar ? <WidgetConfig onComplete={handleAddWidget} /> : <></>}
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
        entity_type
      }
      currentUserAccessRight
      ...WorkspaceManageAccessDialog_authorizedMembers
    }
  `,
});
