import React, { useEffect, useMemo, useState } from 'react';
import * as R from 'ramda';
import { graphql, useFragment } from 'react-relay';
import RGL, { WidthProvider } from 'react-grid-layout';
import Paper from '@mui/material/Paper';
import { v4 as uuid } from 'uuid';
import { useTheme } from '@mui/material/styles';
import DashboardRawViz from './DashboardRawViz';
import DashboardRelationshipsViz from './DashboardRelationshipsViz';
import DashboardAuditsViz from './DashboardAuditsViz';
import DashboardEntitiesViz from './DashboardEntitiesViz';
import DashboardTimeFilters from './DashboardTimeFilters';
import WorkspaceHeader from '../workspaceHeader/WorkspaceHeader';
import { commitMutation, handleError } from '../../../../relay/environment';
import { workspaceMutationFieldPatch } from '../WorkspaceEditionOverview';
import useGranted, { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import WorkspaceWidgetPopover from './WorkspaceWidgetPopover';
import { fromB64, toB64 } from '../../../../utils/String';
import { ErrorBoundary } from '../../Error';
import { deserializeDashboardManifestForFrontend, serializeDashboardManifestForBackend } from '../../../../utils/filters/filtersUtils';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const dashboardLayoutMutation = graphql`
  mutation DashboardLayoutMutation($id: ID!, $input: [EditInput!]!) {
    workspaceFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const dashboardImportWidgetMutation = graphql`
  mutation DashboardWidgetImportMutation(
    $id: ID!
    $input: ImportConfigurationInput!
  ) {
    workspaceWidgetConfigurationImport(id: $id, input: $input) {
      ...Dashboard_workspace
    }
  }
`;

const dashboardFragment = graphql`
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
    ...WorkspaceEditionContainer_workspace
    ...WorkspaceHeaderFragment
  }
`;

const DashboardComponent = ({ data, noToolbar }) => {
  const [commitWidgetImportMutation] = useApiMutation(dashboardImportWidgetMutation);

  const workspace = useFragment(dashboardFragment, data);
  const ReactGridLayout = useMemo(() => WidthProvider(RGL), []);
  const theme = useTheme();

  const [deleting, setDeleting] = useState(false);
  const [idToResize, setIdToResize] = useState();
  const handleResize = (updatedWidget) => setIdToResize(updatedWidget);

  const userHasEditAccess = workspace.currentUserAccessRight === 'admin'
    || workspace.currentUserAccessRight === 'edit';
  const userHasUpdateCapa = useGranted([EXPLORE_EXUPDATE]);
  const userCanEdit = userHasEditAccess && userHasUpdateCapa;
  const isWrite = userCanEdit && !noToolbar;

  useEffect(() => {
    const timeout = setTimeout(() => {
      window.dispatchEvent(new Event('resize'));
    }, 1200);
    return () => {
      clearTimeout(timeout);
    };
  }, []);

  // Map of widget layouts, refreshed when workspace is updated (thanks to useMemo below).
  // We use a local map of layouts to avoid a lot of computation when only changing position
  // or dimension of widgets.
  const [widgetsLayouts, setWidgetsLayouts] = useState({});

  // Deserialized manifest, refreshed when workspace is updated.
  const manifest = useMemo(() => {
    return workspace.manifest && workspace.manifest.length > 0
      ? deserializeDashboardManifestForFrontend(fromB64(workspace.manifest))
      : { widgets: {}, config: {} };
  }, [workspace]);

  // Array of all widgets, refreshed when workspace is updated.
  const widgetsArray = useMemo(() => {
    const widgets = Object.values(manifest.widgets).map((widget) => widget);
    // Sync our local layouts.
    setWidgetsLayouts(
      widgets.reduce((res, widget) => {
        res[widget.id] = widget.layout;
        return res;
      }, {}),
    );
    return widgets;
  }, [manifest]);

  /**
   * Merge a manifest with some layouts and transform it in base64.
   *
   * @param newManifest Manifest to merge with local changes and stringify.
   * @param layouts Local layout changes.
   * @returns {string} Manifest in B64.
   */
  const prepareManifest = (newManifest, layouts) => {
    // Need to sync manifest with local layouts before sending for update.
    // A desync occurs when resizing or moving a widget because in those cases
    // we skip a complete reload to avoid performance issue.
    const syncWidgets = Object.values(newManifest.widgets).reduce((res, widget) => {
      const localLayout = layouts[widget.id];
      res[widget.id] = {
        ...widget,
        layout: localLayout || widget.layout,
      };
      return res;
    }, {});
    const manifestToSave = {
      ...newManifest,
      widgets: syncWidgets,
    };

    const strManifest = serializeDashboardManifestForBackend(manifestToSave);
    return toB64(strManifest);
  };

  const saveManifest = (newManifest, opts = { layouts: widgetsLayouts, noRefresh: false }) => {
    const { layouts, noRefresh } = opts;
    const newManifestEncoded = prepareManifest(newManifest, layouts);
    // Sometimes (in case of layout adjustment) we do not want to re-fetch
    // all the manifest because widgets data is still the same, and it's costly
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
        onCompleted: () => {
          setDeleting(false);
        },
      });
    }
  };

  const handleDateChange = (type, value) => {
    let newManifest = R.assoc(
      'config',
      R.assoc(type, value === 'none' ? null : value, manifest.config),
      manifest,
    );
    if (type === 'relativeDate' && value !== 'none') {
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

  const getNextRow = () => {
    return widgetsArray.reduce((max, { layout }) => {
      const widgetEndRow = layout.y + layout.h;
      return widgetEndRow > max ? widgetEndRow : max;
    }, 0);
  };

  const importWidget = (widgetConfig) => {
    const manifestEncoded = prepareManifest(manifest, widgetsLayouts);
    commitWidgetImportMutation({
      variables: {
        id: workspace.id,
        input: {
          importType: 'widget',
          file: widgetConfig,
          dashboardManifest: manifestEncoded,
        },
      },
      onError: (error) => {
        handleError(error);
      },
    });
  };

  const handleAddWidget = (widgetConfig) => {
    saveManifest({
      ...manifest,
      widgets: {
        ...manifest.widgets,
        [widgetConfig.id]: {
          ...widgetConfig,
          layout: {
            i: widgetConfig.id,
            x: 0,
            y: getNextRow(),
            w: 4,
            h: 2,
          },
        },
      },
    });
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
    const newWidgets = { ...manifest.widgets };
    delete newWidgets[widgetId];
    saveManifest({
      ...manifest,
      widgets: newWidgets,
    });
  };

  const handleDuplicateWidget = (widgetToDuplicate) => {
    handleAddWidget({
      ...widgetToDuplicate,
      id: uuid(),
    });
  };

  const onLayoutChange = (layouts) => {
    if (!deleting) {
      const newLayouts = layouts.reduce((res, layout) => {
        res[layout.i] = layout;
        return res;
      }, {});
      setWidgetsLayouts(newLayouts);
      // Triggering a manifest save with the same manifest.
      // As this function makes a sync between manifest and local layouts
      // it will make the update of layouts modification.
      saveManifest(manifest, { layouts: newLayouts, noRefresh: true });
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
            handleImportWidget={importWidget}
            data={workspace}
            variant="dashboard"
          />
          <div style={{ marginTop: 8 }}>
            <DashboardTimeFilters
              workspace={workspace}
              config={manifest.config}
              handleDateChange={handleDateChange}
            />
          </div>
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
        {widgetsArray.map((widget) => {
          if (!widgetsLayouts[widget.id]) return null;
          return (
            <Paper
              key={widget.id}
              data-grid={widgetsLayouts[widget.id]}
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
    </div>
  );
};

export default DashboardComponent;
