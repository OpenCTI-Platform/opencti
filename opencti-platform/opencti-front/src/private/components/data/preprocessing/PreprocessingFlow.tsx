import React, { FunctionComponent, useCallback, useMemo, useState } from 'react';
import ReactFlow, { Edge, Node } from 'reactflow';
import 'reactflow/dist/style.css';
import Chip from '@mui/material/Chip';
import List from '@mui/material/List';
import ListItemButton from '@mui/material/ListItemButton';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListSubheader from '@mui/material/ListSubheader';
import Drawer from '../../common/drawer/Drawer';
import ItemIcon from '../../../../components/ItemIcon';
import { useFormatter } from '../../../../components/i18n';
import nodeTypes from '../playbooks/types/nodes';
import edgeTypes from '../playbooks/types/edges';
import { PreprocessingFlowEdge, PreprocessingFlowNode, getDefinition, saveDefinition } from './preprocessingStore';
import { PREPROCESSING_COMPONENTS, PreprocessingComponentDef, findComponent } from './preprocessingComponents';

const DEFAULT_VIEWPORT = { x: 200, y: 60, zoom: 1.5 };
const PRO_OPTIONS = { account: 'paid-pro', hideAttribution: true };
const FIT_VIEW_OPTIONS = { padding: 0.8 };
const NODE_Y_SPACING = 120;

interface PreprocessingFlowProps { ruleId: string; }

const groupComponents = (components: PreprocessingComponentDef[]): Array<{ category: string; items: PreprocessingComponentDef[] }> => {
  const grouped: Record<string, PreprocessingComponentDef[]> = {};
  for (const comp of components) { if (!grouped[comp.category]) grouped[comp.category] = []; grouped[comp.category].push(comp); }
  return Object.entries(grouped).map(([category, items]) => ({ category, items }));
};

const buildFlowNodes = (defNodes: PreprocessingFlowNode[], defEdges: PreprocessingFlowEdge[], openPicker: (id: string) => void): { nodes: Node[]; edges: Edge[] } => {
  const sourceIds = new Set(defEdges.map((e) => e.source));
  const flowNodes: Node[] = defNodes.map((n) => {
    const comp = findComponent(n.componentId);
    return { id: n.id, type: 'workflow', position: n.position, data: { name: n.name, description: comp?.description ?? '', component: { icon: comp?.icon ?? 'cog', description: comp?.description ?? '', is_entry_point: comp?.isEntryPoint ?? false, ports: comp?.ports ?? [{ id: 'out', type: 'out' }] }, openConfig: () => {}, openReplace: () => {}, openAddSibling: () => {}, openDelete: () => {} } };
  });
  const flowEdges: Edge[] = defEdges.map((e) => ({ id: e.id, type: 'workflow', source: e.source, sourceHandle: 'out', target: e.target, data: { openConfig: () => {} } }));
  const leafIds = defNodes.map((n) => n.id).filter((id) => !sourceIds.has(id));
  for (const leafId of leafIds) {
    const leafNode = defNodes.find((n) => n.id === leafId);
    const comp = leafNode ? findComponent(leafNode.componentId) : undefined;
    if (comp && Array.isArray(comp.ports) && comp.ports.length === 0) continue;
    const placeholderId = `placeholder-${leafId}`;
    const parentPos = leafNode?.position ?? { x: 0, y: 0 };
    flowNodes.push({ id: placeholderId, type: 'placeholder', position: { x: parentPos.x, y: parentPos.y + NODE_Y_SPACING }, data: { name: '+', configuration: null, component: { is_entry_point: false, ports: [] }, openConfig: () => openPicker(placeholderId) } });
    flowEdges.push({ id: `e-${leafId}-${placeholderId}`, type: 'placeholder', source: leafId, sourceHandle: 'out', target: placeholderId, data: { openConfig: () => {} } });
  }
  return { nodes: flowNodes, edges: flowEdges };
};

const PreprocessingFlow: FunctionComponent<PreprocessingFlowProps> = ({ ruleId }) => {
  const { t_i18n } = useFormatter();
  const [activePlaceholder, setActivePlaceholder] = useState<string | null>(null);
  const [tick, setTick] = useState(0);
  const openPicker = useCallback((id: string) => setActivePlaceholder(id), []);
  const handleSelectComponent = useCallback((component: PreprocessingComponentDef) => {
    if (!activePlaceholder) return;
    const currentDef = getDefinition(ruleId);
    const parentNodeId = activePlaceholder.replace(/^placeholder-/, '');
    const parentNode = currentDef.nodes.find((n) => n.id === parentNodeId);
    const parentPos = parentNode?.position ?? { x: 0, y: 0 };
    const newNodeId = node-${component.id}-${Date.now()};
    saveDefinition(ruleId, { nodes: [...currentDef.nodes, { id: newNodeId, componentId: component.id, name: component.name, position: { x: parentPos.x, y: parentPos.y + NODE_Y_SPACING } }], edges: [...currentDef.edges, { id: e-${parentNodeId}-${newNodeId}, source: parentNodeId, target: newNodeId }] });
    setActivePlaceholder(null); setTick((v) => v + 1);
  }, [activePlaceholder, ruleId]);
  const currentDef = getDefinition(ruleId);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const { nodes, edges } = useMemo(() => buildFlowNodes(currentDef.nodes, currentDef.edges, openPicker), [tick, openPicker]);
  const grouped = groupComponents(PREPROCESSING_COMPONENTS);
  return (
    <div style={{ width: '100%', height: 'calc(100vh - 230px)', minHeight: 500 }}>
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} defaultViewport={DEFAULT_VIEWPORT} minZoom={0.2} fitView fitViewOptions={FIT_VIEW_OPTIONS} nodesDraggable={false} nodesConnectable={false} zoomOnDoubleClick={false} proOptions={PRO_OPTIONS} />
      <Drawer open={activePlaceholder !== null} title={t_i18n('Add component')} onClose={() => setActivePlaceholder(null)}>
        {() => (
          <List>
            {grouped.map(({ category, items }, index) => (
              <React.Fragment key={category}>
                <ListSubheader disableSticky style={index > 0 ? { paddingTop: 8 } : undefined}>{t_i18n(category)}</ListSubheader>
                {items.map((comp) => (
                  <ListItemButton divider key={comp.id} onClick={() => handleSelectComponent(comp)}>
                    <ListItemIcon><ItemIcon type={comp.icon} /></ListItemIcon>
                    <ListItemText
                      primary={<span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>{t_i18n(comp.name)}{comp.isNew && <Chip label="NEW" size="small" color="secondary" style={{ height: 18, fontSize: 10 }} />}</span>}
                      secondary={t_i18n(comp.description)}
                    />
                  </ListItemButton>
                ))}
              </React.Fragment>
            ))}
          </List>
        )}
      </Drawer>
    </div>
  );
};
export default PreprocessingFlow;
