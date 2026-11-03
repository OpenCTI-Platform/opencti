import { Alert, Button, Spinner, Text, TooltipProvider } from '@filigran/design-system';
import { useEffect, useState } from 'react';
import { ReactFlowProvider } from 'reactflow';
import { FilterSidebar } from '../features/filters/FilterSidebar';
import { FindPathPanel } from '../features/find-path/FindPathPanel';
import { NodeInspectorPanel } from '../features/node-inspector/NodeInspectorPanel';
import { SchemaCanvas } from '../features/schema-graph/SchemaCanvas';
import { useSchemaGraphStore } from '../state/schemaGraphStore';
import { useTheme } from '../shared/theme/useTheme';
import { isPopoverOpen } from '../shared/ui/overlays';
import { TopBar } from './TopBar';
import { useAppBootstrap } from './useAppBootstrap';
import './app.css';

const useEscapeToDeselect = () => {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      const state = useSchemaGraphStore.getState();
      const typing = (event.target as HTMLElement | null)?.closest('input, textarea');
      if (typing || state.paletteOpen || state.findPath.open || isPopoverOpen()) return;
      if (state.selectedTypeId) state.selectType(null);
      else if (state.path) state.clearPath();
    };
    window.addEventListener('keydown', onKeyDown, { capture: true });
    return () => window.removeEventListener('keydown', onKeyDown, { capture: true });
  }, []);
};

/** Shell only: the library Header, then the content row (sidebar / canvas / inspector) and top-level states. */
export default function App() {
  const { theme, toggleTheme } = useTheme();
  const { status, schema, retry } = useAppBootstrap();
  const error = useSchemaGraphStore((state) => state.error);
  const selectedType = useSchemaGraphStore((state) => (state.selectedTypeId ? state.schema?.types.get(state.selectedTypeId) : undefined));
  const findPathOpen = useSchemaGraphStore((state) => state.findPath.open);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  useEscapeToDeselect();

  return (
    <TooltipProvider>
      <ReactFlowProvider>
        <TopBar theme={theme} onToggleTheme={toggleTheme} />
        <div className="sv-app">
          {status === 'error' && (
            <div className="sv-app__state">
              <Alert
                severity="error"
                title="The schema could not be loaded"
                description={<>{error} — run <span className="sv-mono">yarn generate</span> to produce public/schema.json.</>}
                action={<Button priority="secondary" size="sm" onClick={retry}>Retry</Button>}
              />
            </div>
          )}
          {(status === 'idle' || status === 'loading') && (
            <div className="sv-app__state">
              <Spinner size="lg" label="Loading the OpenCTI schema" />
              <Text variant="content-compact" className="sv-muted">Loading the OpenCTI schema…</Text>
            </div>
          )}
          {status === 'ready' && schema && (
            <>
              <FilterSidebar schema={schema} collapsed={sidebarCollapsed} onToggleCollapsed={() => setSidebarCollapsed(!sidebarCollapsed)} />
              <main className="sv-app__canvas">
                <SchemaCanvas schema={schema} />
              </main>
              {selectedType && <NodeInspectorPanel schema={schema} type={selectedType} />}
              {findPathOpen && <FindPathPanel schema={schema} />}
            </>
          )}
        </div>
      </ReactFlowProvider>
    </TooltipProvider>
  );
}
