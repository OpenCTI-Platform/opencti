import React, { useState, useMemo, useEffect } from 'react';
import * as R from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import RGL, { WidthProvider } from 'react-grid-layout';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { v4 as uuid } from 'uuid';
import { computerRelativeDate, dayStartDate, parse } from '../../../../utils/Time';
import WorkspaceHeader from '../WorkspaceHeader';
import { commitMutation } from '../../../../relay/environment';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import useGranted, { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import WidgetPopover from './WidgetPopover';
import { fromB64, toB64 } from '../../../../utils/String';
import WidgetConfig from './WidgetConfig';
import WidgetText from './WidgetText';
import StixCoreObjectsMultiVerticalBars from '../../common/stix_core_objects/StixCoreObjectsMultiVerticalBars';
import StixCoreObjectsNumber from '../../common/stix_core_objects/StixCoreObjectsNumber';
import StixCoreObjectsList from '../../common/stix_core_objects/StixCoreObjectsList';
import StixCoreObjectsDistributionList from '../../common/stix_core_objects/StixCoreObjectsDistributionList';
import StixCoreObjectsMultiLineChart from '../../common/stix_core_objects/StixCoreObjectsMultiLineChart';
import StixCoreObjectsMultiAreaChart from '../../common/stix_core_objects/StixCoreObjectsMultiAreaChart';
import StixCoreObjectsTimeline from '../../common/stix_core_objects/StixCoreObjectsTimeline';
import StixCoreObjectsDonut from '../../common/stix_core_objects/StixCoreObjectsDonut';
import StixCoreObjectsHorizontalBars from '../../common/stix_core_objects/StixCoreObjectsHorizontalBars';
import StixCoreObjectsRadar from '../../common/stix_core_objects/StixCoreObjectsRadar';
import StixCoreObjectsMultiHeatMap from '../../common/stix_core_objects/StixCoreObjectsMultiHeatMap';
import StixCoreObjectsTreeMap from '../../common/stix_core_objects/StixCoreObjectsTreeMap';
import StixCoreObjectsMultiHorizontalBars from '../../common/stix_core_objects/StixCoreObjectsMultiHorizontalBars';
import StixDomainObjectBookmarksList from '../../common/stix_domain_objects/StixDomainObjectBookmarksList';
import StixRelationshipsHorizontalBars from '../../common/stix_relationships/StixRelationshipsHorizontalBars';
import StixRelationshipsMultiVerticalBars from '../../common/stix_relationships/StixRelationshipsMultiVerticalBars';
import StixRelationshipsMultiHorizontalBars from '../../common/stix_relationships/StixRelationshipsMultiHorizontalBars';
import StixRelationshipsList from '../../common/stix_relationships/StixRelationshipsList';
import StixRelationshipsDistributionList from '../../common/stix_relationships/StixRelationshipsDistributionList';
import StixRelationshipsNumber from '../../common/stix_relationships/StixRelationshipsNumber';
import StixRelationshipsMultiLineChart from '../../common/stix_relationships/StixRelationshipsMultiLineChart';
import StixRelationshipsMultiAreaChart from '../../common/stix_relationships/StixRelationshipsMultiAreaChart';
import StixRelationshipsTimeline from '../../common/stix_relationships/StixRelationshipsTimeline';
import StixRelationshipsDonut from '../../common/stix_relationships/StixRelationshipsDonut';
import StixRelationshipsRadar from '../../common/stix_relationships/StixRelationshipsRadar';
import StixRelationshipsMultiHeatMap from '../../common/stix_relationships/StixRelationshipsMultiHeatMap';
import StixRelationshipsTreeMap from '../../common/stix_relationships/StixRelationshipsTreeMap';
import StixRelationshipsMap from '../../common/stix_relationships/StixRelationshipsMap';
import AuditsList from '../../common/audits/AuditsList';
import AuditsMultiLineChart from '../../common/audits/AuditsMultiLineChart';
import AuditsMultiAreaChart from '../../common/audits/AuditsMultiAreaChart';
import AuditsMultiVerticalBars from '../../common/audits/AuditsMultiVerticalBars';
import AuditsNumber from '../../common/audits/AuditsNumber';
import AuditsDonut from '../../common/audits/AuditsDonut';
import AuditsHorizontalBars from '../../common/audits/AuditsHorizontalBars';
import AuditsRadar from '../../common/audits/AuditsRadar';
import AuditsMultiHeatMap from '../../common/audits/AuditsMultiHeatMap';
import AuditsTreeMap from '../../common/audits/AuditsTreeMap';
import AuditsDistributionList from '../../common/audits/AuditsDistributionList';
import { ErrorBoundary, SimpleError } from '../../Error';
import {
  deserializeDashboardManifestForFrontend,
  useRemoveIdAndIncorrectKeysFromFilterGroupObject,
  serializeDashboardManifestForBackend,
} from '../../../../utils/filters/filtersUtils';

const useStyles = makeStyles(() => ({
  container: {
    margin: '0 -20px 0 -20px',
  },
  paper: {
    height: '100%',
    margin: 0,
    padding: 20,
    borderRadius: 4,
    display: 'relative',
    overflow: 'hidden',
  },
}));

const COL_WIDTH = 30;

const DashboardComponent = ({ workspace, noToolbar }) => {
  const ReactGridLayout = useMemo(() => WidthProvider(RGL), []);
  const classes = useStyles();
  useEffect(() => {
    const timeout = setTimeout(() => {
      window.dispatchEvent(new Event('resize'));
    }, 1200);
    return () => {
      clearTimeout(timeout);
    };
  }, []);
  const manifest = workspace.manifest && workspace.manifest.length > 0
    ? deserializeDashboardManifestForFrontend(fromB64(workspace.manifest))
    : { widgets: {}, config: {} };
  const saveManifest = (newManifest) => {
    const strManifest = serializeDashboardManifestForBackend(newManifest);
    const newManifestEncoded = toB64(strManifest);
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
  const [deleting, setDeleting] = useState(false);
  const userCanEdit = workspace.currentUserAccessRight === 'admin'
    || workspace.currentUserAccessRight === 'edit';
  const isExploreUpdater = useGranted([EXPLORE_EXUPDATE]);
  const isWrite = isExploreUpdater && userCanEdit && !noToolbar;
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
  const getMaxY = () => {
    return Object.values(manifest.widgets).reduce(
      (max, n) => (n.layout.y > max ? n.layout.y : max),
      0,
    );
  };
  const getMaxX = () => {
    const y = getMaxY();
    const maxX = Object.values(manifest.widgets)
      .filter((n) => n.layout.y === y)
      .reduce((max, n) => (n.layout.x > max ? n.layout.x : max), 0);
    return maxX + 4;
  };
  const handleAddWidget = (widgetManifest) => {
    let maxX = getMaxX();
    let maxY = getMaxY();
    if (maxX >= COL_WIDTH - 4) {
      maxX = 0;
      maxY += 2;
    }
    const newManifest = {
      ...manifest,
      widgets: {
        ...manifest.widgets,
        [widgetManifest.id]: {
          ...widgetManifest,
          layout: { i: widgetManifest.id, x: maxX, y: maxY, w: 4, h: 2 },
        },
      },
    };
    saveManifest(newManifest);
  };
  const handleUpdateWidget = (widgetManifest) => {
    const newManifest = {
      ...manifest,
      widgets: { ...manifest.widgets, [widgetManifest.id]: widgetManifest },
    };
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
            withExportPopover={true}
            isReadOnly={!isWrite}
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
            withExportPopover={true}
            isReadOnly={!isWrite}
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
            withExportPopover={true}
            isReadOnly={!isWrite}
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
            withExportPopover={true}
            isReadOnly={!isWrite}
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
              withExportPopover={true}
              isReadOnly={!isWrite}
            />
          );
        } // TODO from this point
        return (
          <StixCoreObjectsHorizontalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
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
            withExportPopover={true}
            isReadOnly={!isWrite}
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
            withExportPopover={true}
            isReadOnly={!isWrite}
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
            withExportPopover={true}
            isReadOnly={!isWrite}
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
          <StixRelationshipsNumber
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <StixRelationshipsList
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection} // dynamicFrom and dynamicTo TODO
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'distribution-list':
        return (
          <StixRelationshipsDistributionList // TODO idem
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <StixRelationshipsMultiVerticalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'line':
        return (
          <StixRelationshipsMultiLineChart
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'area':
        return (
          <StixRelationshipsMultiAreaChart
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'timeline':
        return (
          <StixRelationshipsTimeline
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'donut':
        return (
          <StixRelationshipsDonut
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'horizontal-bar':
        if (
          widget.dataSelection.length > 1
          && widget.dataSelection[0].attribute === 'internal_id'
        ) {
          return (
            <StixRelationshipsMultiHorizontalBars
              startDate={startDate}
              endDate={endDate}
              dataSelection={widget.dataSelection}
              parameters={widget.parameters}
              variant="inLine"
              withExportPopover={true}
              isReadOnly={!isWrite}
            />
          );
        }
        return (
          <StixRelationshipsHorizontalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'radar':
        return (
          <StixRelationshipsRadar
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'heatmap':
        return (
          <StixRelationshipsMultiHeatMap
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'tree':
        return (
          <StixRelationshipsTreeMap
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'map':
        return (
          <StixRelationshipsMap
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
  const renderAuditsVisualization = (widget, config) => {
    const { relativeDate } = config;
    const startDate = relativeDate
      ? computerRelativeDate(relativeDate)
      : config.startDate;
    const endDate = relativeDate ? getDayStartDate() : config.endDate;
    switch (widget.type) {
      case 'number':
        return (
          <AuditsNumber
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'list':
        return (
          <AuditsList
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'distribution-list':
        return (
          <AuditsDistributionList
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
          />
        );
      case 'vertical-bar':
        return (
          <AuditsMultiVerticalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'line':
        return (
          <AuditsMultiLineChart
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'area':
        return (
          <AuditsMultiAreaChart
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'donut':
        return (
          <AuditsDonut
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'horizontal-bar':
        return (
          <AuditsHorizontalBars
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'radar':
        return (
          <AuditsRadar
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      case 'heatmap':
        return (
          <AuditsMultiHeatMap
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
          />
        );
      case 'tree':
        return (
          <AuditsTreeMap
            startDate={startDate}
            endDate={endDate}
            dataSelection={widget.dataSelection}
            parameters={widget.parameters}
            variant="inLine"
            withExportPopover={true}
            isReadOnly={!isWrite}
          />
        );
      default:
        return 'Not implemented yet';
    }
  };
  const renderRawVisualization = (widget) => {
    switch (widget.type) {
      case 'text':
        return (
          <WidgetText
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
      {isExploreUpdater && userCanEdit ? (
        <ReactGridLayout
          className="layout"
          margin={[20, 20]}
          rowHeight={50}
          cols={12}
          isDraggable={!noToolbar}
          isResizable={!noToolbar}
          onLayoutChange={noToolbar ? () => true : onLayoutChange}
          draggableCancel=".noDrag"
        >
          {R.values(manifest.widgets).map((widget) => {
            let mainEntityTypes = ['Stix-Core-Object'];
            if (widget.perspective === 'relationships') {
              mainEntityTypes = ['Stix-Core-Object', 'stix-core-relationship'];
            } else if (widget.perspective === 'audits') {
              mainEntityTypes = ['History'];
            }
            const removeIdFilterWidget = {
              ...widget,
              dataSelection: widget.dataSelection.map((data) => ({
                ...data,
                filters: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.filters, mainEntityTypes),
                dynamicFrom: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.dynamicFrom, ['Stix-Core-Object']),
                dynamicTo: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.dynamicTo, ['Stix-Core-Object']),
              })),
            };
            return <Paper
              key={widget.id}
              data-grid={widget.layout}
              classes={{ root: classes.paper }}
              variant="outlined"
                   >
              {!noToolbar && (
              <WidgetPopover
                widget={widget}
                manifest={manifest}
                workspace={workspace}
                onUpdate={handleUpdateWidget}
                onDuplicate={handleDuplicateWidget}
                onDelete={() => handleDeleteWidget(widget.id)}
              />
              )}
              <ErrorBoundary
                display={
                  <div style={{ paddingTop: 28 }}>
                    <SimpleError/>
                  </div>
                  }
              >
                {widget.perspective === 'entities'
                    && renderEntitiesVisualization(removeIdFilterWidget, manifest.config)}
                {widget.perspective === 'relationships'
                    && renderRelationshipsVisualization(removeIdFilterWidget, manifest.config)}
                {widget.perspective === 'audits'
                    && renderAuditsVisualization(removeIdFilterWidget, manifest.config)}
                {widget.perspective === null
                    && renderRawVisualization(removeIdFilterWidget, manifest.config)}
              </ErrorBoundary>
            </Paper>;
          })}
        </ReactGridLayout>
      ) : (
        <ReactGridLayout
          className="layout"
          margin={[20, 20]}
          rowHeight={50}
          cols={12}
          isDraggable={false}
          isResizable={false}
          draggableCancel=".noDrag"
        >
          {R.values(manifest.widgets).map((widget) => {
            let mainEntityTypes = ['Stix-Core-Object'];
            if (widget.perspective === 'relationships') {
              mainEntityTypes = ['Stix-Core-Object', 'stix-core-relationship'];
            } else if (widget.perspective === 'audits') {
              mainEntityTypes = ['History'];
            }
            const removeIdFilterWidget = {
              ...widget,
              dataSelection: widget.dataSelection.map((data) => ({
                ...data,
                filters: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.filters, mainEntityTypes),
                dynamicFrom: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.dynamicFrom, ['Stix-Core-Object']),
                dynamicTo: useRemoveIdAndIncorrectKeysFromFilterGroupObject(data.dynamicTo, ['Stix-Core-Object']),
              })),
            };
            return <Paper
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
                  && renderEntitiesVisualization(removeIdFilterWidget, manifest.config)}
                {widget.perspective === 'relationships'
                  && renderRelationshipsVisualization(removeIdFilterWidget, manifest.config)}
                {widget.perspective === 'audits'
                  && renderAuditsVisualization(removeIdFilterWidget, manifest.config)}
                {widget.perspective === null
                  && renderRawVisualization(removeIdFilterWidget, manifest.config)}
              </ErrorBoundary>
            </Paper>;
          })}
        </ReactGridLayout>
      )}
      {!noToolbar && <WidgetConfig onComplete={handleAddWidget} workspace={workspace} />}
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
