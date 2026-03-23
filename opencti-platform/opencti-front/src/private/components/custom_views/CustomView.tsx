import { useEffect, useMemo, useState } from 'react';
import RGL, { WidthProvider } from 'react-grid-layout';
import { Box } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { fromB64 } from '../../../utils/String';
import { deserializeDashboardManifestForFrontend } from '../../../utils/filters/filtersUtils';
import { ErrorBoundary } from '../Error';
import WidgetRawViz from '../widgets/WidgetRawViz';
import WidgetRelationshipsViz from '../widgets/WidgetRelationshipsViz';
import WidgetAuditsViz from '../widgets/WidgetAuditsViz';
import WidgetEntitiesViz from '../widgets/WidgetEntitiesViz';

interface CustomViewComponentProps {
  manifest: string;
}

const CustomViewComponent = ({ manifest: serializedManifest }: CustomViewComponentProps) => {
  const theme = useTheme();

  const ReactGridLayout = useMemo(() => WidthProvider(RGL), []);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [widgetsLayouts, setWidgetsLayouts] = useState<Record<string, any>>({});

  const manifest = useMemo(() => {
    return serializedManifest && serializedManifest.length > 0
      ? deserializeDashboardManifestForFrontend(fromB64(serializedManifest))
      : { widgets: {}, config: {} };
  }, [serializedManifest]);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const widgetsArray: any[] = useMemo(() => {
    return Object.values(manifest.widgets);
  }, [manifest]);

  useEffect(() => {
    setWidgetsLayouts(
      widgetsArray.reduce((res, widget) => {
        res[widget.id] = widget.layout;
        return res;
      }, {}),
    );
  }, [widgetsArray]);

  return (
    <Box
      id="container"
      sx={{
        margin: '0 -20px 0 -20px',
        marginTop: '-20px',
        '& .react-grid-item.react-grid-placeholder': {
          border: `2px solid ${theme.palette.primary.main}`,
          borderRadius: 1,
        },
      }}
    >
      <ReactGridLayout
        className="layout"
        margin={[20, 20]}
        rowHeight={50}
        cols={12}
        isDraggable={false}
        isResizable={false}
      >
        {widgetsArray.map((widget) => {
          if (!widgetsLayouts[widget.id]) return null;
          return (
            <div
              key={widget.id}
              data-grid={widgetsLayouts[widget.id]}
              style={{
                display: 'relative',
              }}
            >
              <ErrorBoundary>
                {widget.perspective === 'entities' && (
                  <WidgetEntitiesViz widget={widget} config={manifest.config} />
                )}
                {widget.perspective === 'relationships' && (
                  <WidgetRelationshipsViz widget={widget} config={manifest.config} />
                )}
                {widget.perspective === 'audits' && (
                  <WidgetAuditsViz widget={widget} config={manifest.config} />
                )}
                {widget.perspective === null && (
                  <WidgetRawViz widget={widget} />
                )}
              </ErrorBoundary>
            </div>
          );
        })}
      </ReactGridLayout>
    </Box>
  );
};

export default CustomViewComponent;
