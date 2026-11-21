import { Paper, Switch } from '@filigran/design-system';
import { Panel, useReactFlow } from 'reactflow';
import { useSchemaGraphStore } from '../../state/schemaGraphStore';
import { IconAction } from '../../shared/ui/IconAction';
import { PathBanner } from './PathBanner';

export const CanvasControls = () => {
  const { zoomIn, zoomOut } = useReactFlow();
  const showRelations = useSchemaGraphStore((state) => state.showRelations);
  const showInheritance = useSchemaGraphStore((state) => state.showInheritance);
  const includeRefs = useSchemaGraphStore((state) => state.includeRefs);
  const direction = useSchemaGraphStore((state) => state.direction);
  const hasPath = useSchemaGraphStore((state) => state.path !== null);
  const isEmpty = useSchemaGraphStore((state) => state.pinnedTypeIds.length === 0);
  const setShowRelations = useSchemaGraphStore((state) => state.setShowRelations);
  const setShowInheritance = useSchemaGraphStore((state) => state.setShowInheritance);
  const setIncludeRefs = useSchemaGraphStore((state) => state.setIncludeRefs);
  const setDirection = useSchemaGraphStore((state) => state.setDirection);
  const requestCamera = useSchemaGraphStore((state) => state.requestCamera);
  const clearCanvas = useSchemaGraphStore((state) => state.clearCanvas);

  return (
    <>
      <Panel position="top-left">
        {hasPath ? <PathBanner /> : (
          <Paper elevation={2} padding={8} className="sv-canvas-toolbar" aria-label="Display options">
            <Switch checked={showRelations} onCheckedChange={setShowRelations} label="Relations" />
            <Switch checked={showInheritance} onCheckedChange={setShowInheritance} label="Inheritance" />
            <Switch checked={includeRefs} onCheckedChange={setIncludeRefs} label="Ref attributes" />
            <span className="sv-canvas-toolbar__divider" />
            <IconAction
              icon={direction === 'TB' ? 'arrow-down' : 'arrow-right'}
              label={direction === 'TB' ? 'Top to bottom layout, switch to left to right' : 'Left to right layout, switch to top to bottom'}
              onClick={() => setDirection(direction === 'TB' ? 'LR' : 'TB')}
            />
            <IconAction icon="trash-2" label="Clear the canvas" onClick={clearCanvas} disabled={isEmpty} />
          </Paper>
        )}
      </Panel>
      <Panel position="bottom-left">
        <Paper elevation={2} padding={8} className="sv-zoom-controls" aria-label="Zoom">
          <IconAction icon="plus" label="Zoom in" onClick={() => zoomIn({ duration: 150 })} />
          <IconAction icon="minus" label="Zoom out" onClick={() => zoomOut({ duration: 150 })} />
          <IconAction icon="maximize-2" label="Fit to screen" onClick={() => requestCamera(null)} />
        </Paper>
      </Panel>
    </>
  );
};
