import ReactGridLayout, { useContainerWidth } from 'react-grid-layout';
import { Box } from '@mui/material';
import DashboardViz from '@components/workspaces/dashboards/DashboardViz';
import useDashboard from '@components/widgets/useDashboard';

const CONTAINER_STYLE = {
  // Compensate gridConfig margins to avoid outer margins
  margin: '0 -20px 0 -20px',
  marginTop: '-20px',
};

const WIDGET_STYLE = {
  display: 'relative',
};

interface CustomViewComponentProps {
  manifest: string;
}

/**
 * Displays a custom view from its serialized content
 */
const CustomViewComponent = ({ manifest }: CustomViewComponentProps) => {
  const { width, containerRef } = useContainerWidth();
  const { config, widgetsArray, widgetsLayouts } = useDashboard(manifest);
  return (
    <Box ref={containerRef} sx={CONTAINER_STYLE}>
      <ReactGridLayout
        className="layout"
        width={width}
        layout={Object.values(widgetsLayouts)}
        gridConfig={{ margin: [20, 20], rowHeight: 50, cols: 12 }}
        resizeConfig={{ enabled: false }}
        dragConfig={{ enabled: false }}
        dropConfig={{ enabled: false }}
      >
        {widgetsArray.map((widget) => (
          <div key={widget.id} style={WIDGET_STYLE}>
            <DashboardViz
              key={widget.id}
              widget={widget}
              config={config}
            />
          </div>
        ))}
      </ReactGridLayout>
    </Box>
  );
};

export default CustomViewComponent;
