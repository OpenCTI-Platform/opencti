import { useEffect, useState, useCallback, useRef } from 'react';
import ReactFlow, {
  useNodesState,
  useEdgesState,
  addEdge,
  type Connection,
  type Edge,
  type Node,
  Background,
  Controls,
  MiniMap,
  ReactFlowProvider,
  useReactFlow,
} from 'reactflow';
import 'reactflow/dist/style.css';
import dagre from 'dagre';
import CustomNode from './CustomNode';
import TargetGroupNode from './TargetGroupNode';

const nodeTypes = {
  entity: CustomNode,
  relationship: CustomNode,
  'target-group': TargetGroupNode,
};

// Layout function
const getLayoutedElements = (nodes: Node[], edges: Edge[], direction = 'TB') => {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));

  // 1. Simple Uniform Layout: Fixed Width (Doubled Weight)
  const uniformWidth = 500;

  dagreGraph.setGraph({
    rankdir: direction,
    ranksep: 60, // Increased from 30 to 60 to prevent edge label overlap or tight spacing
    nodesep: 50, // Increased from 30 to 50 for safety
    ranker: 'tight-tree'
  });

  nodes.forEach((node) => {
    // Height is pre-calculated in the mapping step
    const h = node.height || 60;
    dagreGraph.setNode(node.id, { width: uniformWidth, height: h });
  });

  edges.forEach((edge) => {
    // Reverse inheritance edges for Dagre Layout ONLY
    // We want Parents (Target) to be ABOVE Children (Source).
    // Standard Dagre 'TB' places Source above Target.
    // So we tell Dagre: Target -> Source.
    if (edge.label === 'is-a') {
      dagreGraph.setEdge(edge.target, edge.source);
    } else {
      dagreGraph.setEdge(edge.source, edge.target);
    }
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    const h = node.height || 60;

    return {
      ...node,
      position: {
        x: nodeWithPosition.x - (uniformWidth / 2),
        y: nodeWithPosition.y - (h / 2),
      },
      style: {
        ...node.style,
        width: uniformWidth, // Force visualization width
        opacity: 1
      },
    };
  });

  return { nodes: layoutedNodes, edges };
};

const SchemaFlow = () => {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [schemaData, setSchemaData] = useState<{ nodes: Node[]; edges: Edge[] } | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterMode, setFilterMode] = useState<'all' | 'entities' | 'relationships'>('all');
  const [inputText, setInputText] = useState(''); // Local input state
  const { fitView, getViewport } = useReactFlow();

  const handleSearch = useCallback(() => {
    setSearchTerm(inputText);
  }, [inputText]);

  // Viewport Stats Logic
  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const [visibleStats, setVisibleStats] = useState({ nodes: 0, edges: 0 });
  const isSimplifiedRef = useRef(false);
  const [fps, setFps] = useState(60);

  // FPS Counter Logic
  useEffect(() => {
    let frameCount = 0;
    let lastTime = performance.now();
    let animFrameId: number;

    const loop = () => {
      const now = performance.now();
      frameCount++;

      if (now - lastTime >= 1000) {
        setFps(Math.round(frameCount * 1000 / (now - lastTime)));
        frameCount = 0;
        lastTime = now;
      }
      animFrameId = requestAnimationFrame(loop);
    };

    loop();
    return () => cancelAnimationFrame(animFrameId);
  }, []);

  const updateVisibleStats = useCallback(() => {
    if (!reactFlowWrapper.current) return;

    const { x, y, zoom } = getViewport();
    const { offsetWidth, offsetHeight } = reactFlowWrapper.current;

    // Calculate visible rectangle in world coordinates
    const visibleRect = {
      x: -x / zoom,
      y: -y / zoom,
      width: offsetWidth / zoom,
      height: offsetHeight / zoom,
    };

    const visibleNodeIds = new Set<string>();

    const visibleNodesCount = nodes.filter((n) => {
      // Simple AABB intersection
      const nX = n.position.x;
      const nY = n.position.y;
      const nW = n.width || 500;
      const nH = n.height || 60;

      const isVisible = (
        nX < visibleRect.x + visibleRect.width &&
        nX + nW > visibleRect.x &&
        nY < visibleRect.y + visibleRect.height &&
        nY + nH > visibleRect.y
      );
      if (isVisible) visibleNodeIds.add(n.id);
      return isVisible;
    }).length;

    // LOD Logic: If > 40 nodes visible, simplify visuals
    const shouldSimplify = visibleNodesCount > 40;

    // Only update nodes if the state effectively changes to avoid infinite loop
    if (shouldSimplify !== isSimplifiedRef.current) {
      isSimplifiedRef.current = shouldSimplify;

      // Defer this update slightly to avoid interfering with current render cycle or use functional update
      requestAnimationFrame(() => {
        setNodes((nds) => nds.map(n => ({
          ...n,
          data: { ...n.data, simplified: shouldSimplify }
        })));

        // Hide inheritance edges in Simplified Mode to reduce SVG complexity
        setEdges((eds) => eds.map(e => ({
          ...e,
          hidden: shouldSimplify && e.label === 'is-a',
          style: {
            ...e.style,
            // Ensure opacity is managed if needed, but 'hidden' prop is best for performance
          }
        })));
      });
    }

    // Count edges where BOTH source and target are visible
    // OPTIMIZATION: If simplified (many nodes), hide 'is-a' inheritance edges to reduce visual noise and DOM count
    const visibleEdgesCount = edges.filter(e =>
      visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target) &&
      (!shouldSimplify || e.label !== 'is-a')
    ).length;

    setVisibleStats({ nodes: visibleNodesCount, edges: visibleEdgesCount });
  }, [nodes, edges, getViewport, setNodes, setEdges]);

  // Update stats on move end
  const onMoveEnd = useCallback(() => {
    updateVisibleStats();
  }, [updateVisibleStats]);

  // Update stats on initial load / layout change
  useEffect(() => {
    // Immediate check for quick updates
    const timer1 = setTimeout(() => {
      updateVisibleStats();
    }, 100);

    // Delayed check to catch end of animations (e.g. fitView takes ~800-1000ms)
    const timer2 = setTimeout(() => {
      updateVisibleStats();
    }, 1200);

    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
    };
  }, [nodes, edges, updateVisibleStats]);

  // Jump to node handler
  useEffect(() => {
    const handleJump = (e: Event) => {
      const { nodeId } = (e as CustomEvent).detail;
      const targetNode = nodes.find(n => n.id === nodeId && !n.data.isDuplicate);
      if (targetNode) {
        setNodes((nds) => nds.map((n) => ({
          ...n,
          selected: n.id === targetNode.id
        })));

        fitView({ nodes: [{ id: targetNode.id }], duration: 800, padding: 0.2, minZoom: 0.01, maxZoom: 4 });
      }
    };

    window.addEventListener('jumpToNode', handleJump);
    return () => window.removeEventListener('jumpToNode', handleJump);
  }, [nodes, setNodes, fitView]);

  useEffect(() => {
    fetch('./schema.json')
      .then((res) => res.json())
      .then((data) => {
        setSchemaData(data);

        const initialNodes = data.nodes.map((n: Node) => ({
          ...n,
          type: n.type === 'relationship' ? 'relationship' : 'entity',
          position: { x: 0, y: 0 }
        }));

        const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
          initialNodes,
          data.edges
        );

        setNodes(layoutedNodes);
        setEdges(layoutedEdges);

        // Initial fit (triggers stats update via effect)
        setTimeout(() => fitView({ duration: 800, padding: 0.2 }), 200);
      });
  }, [setNodes, setEdges, fitView]);

  // Filtering and Layout Recalculation
  // State for expand logic
  // Record<NodeId, boolean>: true = Force Expand, false = Force Collapse, undefined = Default
  const [nodeOverrides, setNodeOverrides] = useState<Record<string, boolean>>({});

  // Ref to track previous dependencies for conditional zooming
  const prevDepsRef = useRef({ searchTerm, filterMode, schemaData });

  // Handle Jump: Set search, and force expand the target
  const onJumpToNode = useCallback((event: Event) => {
    const customEvent = event as CustomEvent;
    const nodeId = customEvent.detail.nodeId;
    setSearchTerm(nodeId);
    setInputText(nodeId); // Sync input immediately
    setNodeOverrides(prev => ({
      ...prev,
      [nodeId]: true // Force Expand on Jump
    }));
  }, []);

  // Handle Toggle: Toggle specific node
  const onToggleNode = useCallback((event: Event) => {
    const customEvent = event as CustomEvent;
    const { nodeId, isExpanded } = customEvent.detail;

    setNodeOverrides(prev => ({
      ...prev,
      [nodeId]: !isExpanded // Invert current state
    }));
  }, []);

  useEffect(() => {
    window.addEventListener('jumpToNode', onJumpToNode);
    window.addEventListener('toggleNode', onToggleNode);
    return () => {
      window.removeEventListener('jumpToNode', onJumpToNode);
      window.removeEventListener('toggleNode', onToggleNode);
    };
  }, [onJumpToNode, onToggleNode]);

  // Filtering and Layout Recalculation
  useEffect(() => {
    if (!schemaData) return;

    const term = searchTerm.toLowerCase();

    // 1. Identify Seed Matches
    let initialMatches = [];

    // Check for Exact Match First
    const exactMatch = schemaData.nodes.find((n: Node) =>
      n.id.toLowerCase() === term || n.data.label.toLowerCase() === term
    );

    if (exactMatch && term.length > 0) {
      initialMatches = [exactMatch];
    } else {
      initialMatches = schemaData.nodes.filter((n: Node) => {
        if (term) {
          return n.data.label.toLowerCase().includes(term);
        }
        return true;
      });
    }

    // Apply Type Filters
    initialMatches = initialMatches.filter((n: Node) => {
      if (filterMode === 'entities') {
        if (n.type === 'relationship') return false;
        if (n.data.isDuplicate) return false;
      } else if (filterMode === 'relationships') {
        if (n.type !== 'relationship') return false;
      }
      return true;
    });

    const visibleNodeIds = new Set<string>(initialMatches.map((n: Node) => n.id));

    // 2. Expand Context
    if (exactMatch) {
      visibleNodeIds.clear();
      visibleNodeIds.add(exactMatch.id);

      // A. Add Ancestors
      const ancestorQueue = [exactMatch.id];
      const visitedAncestors = new Set<string>([exactMatch.id]);

      while (ancestorQueue.length > 0) {
        const currentId = ancestorQueue.shift();
        if (!currentId) continue;

        schemaData.edges.forEach((e: Edge) => {
          if (e.source === currentId && e.label === 'is-a') {
            if (!visitedAncestors.has(e.target)) {
              visibleNodeIds.add(e.target);
              visitedAncestors.add(e.target);
              ancestorQueue.push(e.target);
            }
          }
        });
      }

      // B. Add Direct Neighbors
      schemaData.edges.forEach((e: Edge) => {
        const isConnected = e.source === exactMatch.id || e.target === exactMatch.id;
        if (isConnected) {
          visibleNodeIds.add(e.source);
          visibleNodeIds.add(e.target);
        }
      });

      // C. Expand Targets of Visible Relationship Nodes
      schemaData.edges.forEach((e: Edge) => {
        if (visibleNodeIds.has(e.source)) {
          const sourceNode = schemaData.nodes.find((n: Node) => n.id === e.source);
          if (sourceNode && sourceNode.type === 'relationship') {
            visibleNodeIds.add(e.target);
          }
        }
      });

    } else if (searchTerm) {
      let changed = true;
      let iterations = 0;

      while (changed && iterations < 2) {
        changed = false;
        schemaData.edges.forEach((e: Edge) => {
          const sourceVisible = visibleNodeIds.has(e.source);
          const targetVisible = visibleNodeIds.has(e.target);

          if (sourceVisible && !targetVisible) {
            visibleNodeIds.add(e.target);
            changed = true;
          } else if (!sourceVisible && targetVisible) {
            visibleNodeIds.add(e.source);
            changed = true;
          }
        });
        iterations++;
      }
    }

    // 3. Finalize Visible Set
    const visibleNodes = schemaData.nodes.filter((n: Node) => visibleNodeIds.has(n.id));

    // 4. Identify visible edges
    const visibleEdges = schemaData.edges.filter((e: Edge) => {
      return visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target);
    }).map((e: Edge) => {
      if (e.label === 'is-a') {
        return {
          ...e,
          type: 'straight', // Simpler geometry for performance
          sourceHandle: 's-top',
          targetHandle: 't-bottom',
          style: { ...e.style, stroke: '#94a3b8', strokeDasharray: '5,5' }
        };
      }
      return {
        ...e,
        sourceHandle: 's-bottom',
        targetHandle: 't-top'
      };
    });

    // Exact Match Logic
    const exactMatchNode = schemaData.nodes.find((n: Node) =>
      n.id.toLowerCase() === term || n.data.label.toLowerCase() === term
    );

    const ancestorIds = new Set<string>();

    if (exactMatchNode) {
      const queue = [exactMatchNode.id];
      const visited = new Set<string>([exactMatchNode.id]);

      while (queue.length > 0) {
        const currentId = queue.shift();
        if (!currentId) continue;

        schemaData.edges.forEach((e: Edge) => {
          const isInheritance = e.label === 'is-a';
          if (e.source === currentId && isInheritance) {
            if (!visited.has(e.target)) {
              ancestorIds.add(e.target);
              visited.add(e.target);
              queue.push(e.target);
            }
          }
        });
      }
    }

    // 5. Re-calculate Layout
    const nodesForLayout = visibleNodes.map((n: Node) => {
      // DEFAULT: Collapsed. Only expand if explicitly overridden by user or Search Jump.
      const forceExpand = nodeOverrides[n.id] === true;

      let height = 60;
      if (forceExpand) {
        const attrCount = n.data.attributes?.length || 0;
        height = 70 + (attrCount * 36);
      }

      if (n.type === 'target-group') {
        const itemCount = n.data.items?.length || 0;
        height = 50 + (itemCount * 35);
      }

      return {
        ...n,
        data: {
          ...n.data,
          forceExpanded: forceExpand
        },
        width: 500,
        height: height,
        position: { x: 0, y: 0 }
      };
    });

    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
      nodesForLayout,
      visibleEdges
    );

    // 6. Update State
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);

    // 5. Auto Zoom - CONDITIONAL
    // Only zoom if major context changed (search, filter, new data)
    // Do NOT zoom if just toggling expand (which just updates layout)
    const prevDeps = prevDepsRef.current;
    const shouldZoom =
      prevDeps.searchTerm !== searchTerm ||
      prevDeps.filterMode !== filterMode ||
      prevDeps.schemaData !== schemaData;

    if (shouldZoom && layoutedNodes.length > 0) {
      setTimeout(() => {
        fitView({
          duration: 800,
          padding: 0.2,
          minZoom: 0.01,
          maxZoom: 4
        });
      }, 300);
    }

    // Update refs
    prevDepsRef.current = { searchTerm, filterMode, schemaData };

  }, [searchTerm, filterMode, schemaData, setNodes, setEdges, fitView, nodeOverrides]);

  const onConnect = useCallback(
    (params: Connection | Edge) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  return (
    <div style={{ width: '100%', height: '100vh' }} ref={reactFlowWrapper}>
      <div className="search-bar">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%' }}>
          <div style={{ display: 'flex', gap: '8px', width: '100%' }}>
            <input
              className="search-input"
              placeholder="Search entities..."
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              style={{ flex: 1 }}
            />
            <button
              className="filter-btn active"
              onClick={handleSearch}
              style={{ flex: 'none', width: '36px', height: '36px', padding: '0', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="11" cy="11" r="8"></circle>
                <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
              </svg>
            </button>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className={`filter-btn ${filterMode === 'all' ? 'active' : ''}`}
              onClick={() => setFilterMode('all')}
            >
              All
            </button>
            <button
              className={`filter-btn ${filterMode === 'entities' ? 'active' : ''}`}
              onClick={() => setFilterMode('entities')}
            >
              Entities Only
            </button>
            <button
              className={`filter-btn ${filterMode === 'relationships' ? 'active' : ''}`}
              onClick={() => setFilterMode('relationships')}
            >
              Relationships Only
            </button>
          </div>
        </div>
      </div>

      <div className="stats-panel">
        <div className="stats-item">
          <span className="stats-label">Nodes:</span>
          <span className="stats-value">{visibleStats.nodes}</span>
        </div>
        <div className="stats-item">
          <span className="stats-label">Links:</span>
          <span className="stats-value">{visibleStats.edges}</span>
        </div>
        <div className="stats-item">
          <span className="stats-label">FPS:</span>
          <span className="stats-value" style={{ color: fps < 30 ? '#ef4444' : '#10b981' }}>{fps}</span>
        </div>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onMoveEnd={onMoveEnd}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.01}
        maxZoom={4}
        onlyRenderVisibleElements={true}
        nodesConnectable={false}
        nodesDraggable={false}
        elementsSelectable={true}
      >
        <Background color="#aaa" gap={16} />
        <Controls />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === 'relationship') return '#ec4899';
            return '#38bdf8';
          }}
          maskColor="rgba(0, 0, 0, 0.4)"
        />
      </ReactFlow>
    </div>
  );
};

export default function App() {
  return (
    <ReactFlowProvider>
      <SchemaFlow />
    </ReactFlowProvider>
  );
}
