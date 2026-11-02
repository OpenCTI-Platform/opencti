import ReactGridLayout, { useContainerWidth } from 'react-grid-layout';
import Box from '@mui/material/Box';
import useDashboard from './useDashboard';
import DashboardWidgetPopover from './DashboardWidgetPopover';
import DashboardViz from './DashboardViz';
import DashboardWidgetVariablesMarker from './DashboardWidgetVariablesMarker';
import type { DashboardLike } from './dashboard-types';
import type { WidgetHost } from '../../utils/widget/widget';

type DashboardContentProps = {
  helpers: ReturnType<typeof useDashboard>;
  host: WidgetHost;
  entity: DashboardLike;
  isEditable: boolean;
  refreshRate?: number | null;
  // Names of the variables each widget filters on: a widget listed here shows a marker. Undefined: no marker.
  variableNamesByWidget?: ReadonlyMap<string, readonly string[]>;
};

const DashboardContent = ({
  entity,
  isEditable,
  refreshRate,
  variableNamesByWidget,
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
          // Centered together on one row: in the header action slot (a block), the icon would sit on the text baseline.
          const action = variableNamesByWidget ? (
            <Box component="span" sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5, verticalAlign: 'top' }}>
              <DashboardWidgetVariablesMarker names={variableNamesByWidget.get(widget.id) ?? []} />
              {popover}
            </Box>
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
