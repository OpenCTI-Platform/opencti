import { Paper, Text } from '@filigran/design-system';
import { Panel } from 'reactflow';
import type { VisibleGraph } from './buildVisibleGraph';
import { useFps, useZoomPercent } from './hooks/useVisibleStats';

export const CanvasStatusBar = ({ graph }: { graph: VisibleGraph }) => {
  const zoom = useZoomPercent();
  const fps = useFps(import.meta.env.DEV);
  const typeCount = graph.nodes.filter((node) => node.kind === 'type').length;
  const relationCount = graph.edges.reduce((count, edge) => count + (edge.kind === 'relation' ? edge.relations.length : 0), 0);

  return (
    <Panel position="bottom-center">
      <Paper elevation={2} padding={8} className="sv-status-bar" aria-live="polite">
        <Text variant="content-caption" as="span" className="sv-muted">{typeCount} types</Text>
        <Text variant="content-caption" as="span" className="sv-muted">{relationCount} relations</Text>
        <Text variant="content-caption" as="span" className="sv-muted">{zoom}%</Text>
        {fps !== null && <Text variant="content-caption" as="span" className="sv-muted">{fps} fps</Text>}
      </Paper>
    </Panel>
  );
};
