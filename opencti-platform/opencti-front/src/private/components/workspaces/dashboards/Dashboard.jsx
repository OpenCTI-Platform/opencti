import React, { useEffect, useMemo, useState } from 'react';
import * as R from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import RGL, { WidthProvider } from 'react-grid-layout';
import Paper from '@mui/material/Paper';
import { v4 as uuid } from 'uuid';
import { useTheme } from '@mui/material/styles';
import DashboardRawViz from './DashboardRawViz';
import DashboardRelationshipsViz from './DashboardRelationshipsViz';
import DashboardAuditsViz from './DashboardAuditsViz';
import DashboardEntitiesViz from './DashboardEntitiesViz';
import DashboardTimeFilters from './DashboardTimeFilters';
import { parse } from '../../../../utils/Time';
import WorkspaceHeader from '../WorkspaceHeader';
import { commitMutation } from '../../../../relay/environment';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import useGranted, { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import WorkspaceWidgetPopover from './WorkspaceWidgetPopover';
import { fromB64, toB64 } from '../../../../utils/String';
import WorkspaceWidgetConfig from './WorkspaceWidgetConfig';
import { ErrorBoundary } from '../../Error';
import { deserializeDashboardManifestForFrontend, serializeDashboardManifestForBackend } from '../../../../utils/filters/filtersUtils';
import useHelper from '../../../../utils/hooks/useHelper';

const COL_WIDTH = 30;

const dashboardLayoutMutation = graphql`
  mutation DashboardLayoutMutation($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const DashboardComponent = ({ workspace, noToolbar }) => {
  const ReactGridLayout = useMemo(() => WidthProvider(RGL), []);
  const theme = useTheme();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const [deleting, setDeleting] = useState(false);
  const [idToResize, setIdToResize] = useState();
  const handleResize = (updatedWidget) => setIdToResize(updatedWidget);

  useEffect(() => {
    const timeout = setTimeout(() => {
      window.dispatchEvent(new Event('resize'));
    }, 1200);
    return () => {
      clearTimeout(timeout);
    };
  }, []);

  const manifest = useMemo(() => {
    return workspace.manifest && workspace.manifest.length > 0
      ? deserializeDashboardManifestForFrontend(fromB64(workspace.manifest))
      : { widgets: {}, config: {} };
  }, [workspace]);

  const widgets = useMemo(() => {
    return Object.values(manifest.widgets).map((widget) => widget);
  }, [manifest]);

  const userHasEditAccess = workspace.currentUserAccessRight === 'admin'
    || workspace.currentUserAccessRight === 'edit';
  const userHasUpdateCapa = useGranted([EXPLORE_EXUPDATE]);
  const userCanEdit = userHasEditAccess && userHasUpdateCapa;
  const isWrite = userCanEdit && !noToolbar;

  const saveManifest = (newManifest, noRefresh = false) => {
    const strManifest = serializeDashboardManifestForBackend(newManifest);
    const newManifestEncoded = toB64(strManifest);
    // Sometimes (in case of layout adjustment) we do not want to re-fetch
    // all the manifest because widgets data is still the same and it's costly
    // in performance.
    const mutation = noRefresh ? dashboardLayoutMutation : workspaceMutationFieldPatch;
    if (workspace.manifest !== newManifestEncoded) {
      commitMutation({
        mutation,
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
      saveManifest(newManifest, true);
    }
  };

  const paperStyle = {
    height: '100%',
    margin: 0,
    padding: theme.spacing(2),
    borderRadius: 4,
    display: 'relative',
    overflow: 'hidden',
  };

  return (
    <div
      id="container"
      style={{
        margin: '0 -20px 0 -20px',
        marginTop: noToolbar ? -20 : 10,
      }}
    >
      {!noToolbar && (
        <>
          <WorkspaceHeader
            handleAddWidget={handleAddWidget}
            workspace={workspace}
            variant="dashboard"
            config={manifest.config}
            handleDateChange={handleDateChange}
          />
          {isFABReplaced && (
            <div style={{ marginTop: 8 }}>
              <DashboardTimeFilters
                workspace={workspace}
                config={manifest.config}
                handleDateChange={handleDateChange}
              />
            </div>
          )}
        </>
      )}
      <ReactGridLayout
        className="layout"
        margin={[20, 20]}
        rowHeight={50}
        cols={12}
        draggableCancel=".noDrag"
        isDraggable={userCanEdit ? !noToolbar : false}
        isResizable={userCanEdit ? !noToolbar : false}
        onLayoutChange={userCanEdit && !noToolbar ? onLayoutChange : () => true}
        onResizeStart={userCanEdit ? (_, { i }) => handleResize(i) : undefined}
        onResizeStop={userCanEdit ? handleResize : undefined}
      >
        {widgets.map((widget) => {
          return (
            <Paper
              key={widget.id}
              data-grid={widget.layout}
              style={paperStyle}
              variant="outlined"
            >
              {userCanEdit && !noToolbar && (
                <WorkspaceWidgetPopover
                  widget={widget}
                  manifest={manifest}
                  workspace={workspace}
                  onUpdate={handleUpdateWidget}
                  onDuplicate={handleDuplicateWidget}
                  onDelete={() => handleDeleteWidget(widget.id)}
                />
              )}
              <ErrorBoundary>
                {widget.id === idToResize ? <div /> : (
                  <>
                    {widget.perspective === 'entities' && (
                      <DashboardEntitiesViz
                        widget={widget}
                        isReadonly={!isWrite}
                        config={manifest.config}
                      />
                    )}
                    {widget.perspective === 'relationships' && (
                      <DashboardRelationshipsViz
                        widget={widget}
                        isReadonly={!isWrite}
                        config={manifest.config}
                      />
                    )}
                    {widget.perspective === 'audits' && (
                      <DashboardAuditsViz
                        widget={widget}
                        isReadonly={!isWrite}
                        config={manifest.config}
                      />
                    )}
                    {widget.perspective === null && (
                      <DashboardRawViz widget={widget} />
                    )}
                  </>
                )}
              </ErrorBoundary>
            </Paper>
          );
        })}
      </ReactGridLayout>

      {!noToolbar && userCanEdit && !isFABReplaced && (
        <WorkspaceWidgetConfig
          onComplete={handleAddWidget}
          workspace={workspace}
        />
      )}
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
