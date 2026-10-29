import ReactGridLayout, { useContainerWidth } from 'react-grid-layout';
import Box from '@mui/material/Box';
import useDashboard from './useDashboard';
import DashboardWidgetPopover from './DashboardWidgetPopover';
import DashboardViz from './DashboardViz';
import DashboardWidgetVariablesMarker from './DashboardWidgetVariablesMarker';
import { getWidgetVariableNames } from './dashboardWidgetVariableUsage';
import type { DashboardLike, DashboardVariable } from './dashboard-types';
import type { WidgetHost } from '../../utils/widget/widget';
import { useFormatter } from '../i18n';

type DashboardContentProps = {
  helpers: ReturnType<typeof useDashboard>;
  host: WidgetHost;
  entity: DashboardLike;
  isEditable: boolean;
  refreshRate?: number | null;
  // The variables of the dashboard: each widget filtering on some of them shows a marker. Undefined: no marker.
  usageMarkerVariables?: readonly DashboardVariable[];
};

const DashboardContent = ({
  entity,
  isEditable,
  refreshRate,
  usageMarkerVariables,
  helpers: {
    widgetsLayouts,
    widgetsArray,
    handleUpdateWidget,
    handleLayoutChange,
    handleResize,
    handleDuplicateWidget,
    handleDeleteWidget,
    handleExportWidget,
    idToResize,
    config,
  },
  host,
}: DashboardContentProps) => {
  const { t_i18n } = useFormatter();
  const { width, containerRef } = useContainerWidth();
  return (
    <Box
      ref={containerRef}
      sx={{
        marginBottom: '20px',
        ...(isEditable
          ? {
              '& .react-grid-item.react-grid-placeholder': {
                border: '2px solid',
                borderColor: 'primary.main',
                borderRadius: 1,
              } }
          : {}),
      }}
    >
      <ReactGridLayout
        className="layout"
        width={width}
        layout={Object.values(widgetsLayouts)}
        gridConfig={{ margin: [20, 20], rowHeight: 62, cols: 12, containerPadding: [0, 0] }}
        dragConfig={{ enabled: isEditable, cancel: '.noDrag' }}
        resizeConfig={{ enabled: isEditable }}
        onLayoutChange={isEditable ? handleLayoutChange : () => true}
        onResizeStart={isEditable ? (_, layoutItem) => handleResize(layoutItem?.i ?? null) : undefined}
        onResizeStop={isEditable ? () => handleResize(null) : undefined}
      >
        {widgetsArray.map((widget) => {
          if (!widgetsLayouts[widget.id]) return null;
          const popover = isEditable && (
            <DashboardWidgetPopover
              widget={widget}
              entity={entity}
              onUpdate={handleUpdateWidget}
              onDuplicate={handleDuplicateWidget}
              onDelete={() => handleDeleteWidget(widget.id)}
              onExport={handleExportWidget}
              host={host}
            />
          );
          // The marker is for everyone who sees the widget, the menu for those who may edit it.
          const action = usageMarkerVariables ? (
            <>
              <DashboardWidgetVariablesMarker names={getWidgetVariableNames(widget, usageMarkerVariables, t_i18n)} />
              {popover}
            </>
          ) : popover;

          return (
            <div key={widget.id}>
              {isEditable && widget.id === idToResize ? <div /> : (
                <DashboardViz
                  widget={widget}
                  host={host}
                  config={config}
                  popover={action}
                  refreshRate={refreshRate}
                />
              )}
            </div>
          );
        })}
      </ReactGridLayout>
    </Box>
  );
};

export default DashboardContent;
