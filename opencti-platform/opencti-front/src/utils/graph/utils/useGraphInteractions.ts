import { useGraphContext, GraphState } from './GraphContext';
import type { GraphNode, LibGraphProps } from '../graph.types';
import { RectangleSelectionProps } from '../components/RectangleSelection';

const useGraphInteractions = () => {
  const {
    graphData,
    graphRef,
    graphState,
    selectedLinks,
    selectedNodes,
    setGraphStateProp,
    setSelectedLinks,
    setSelectedNodes,
    addSelectedLink,
    addSelectedNode,
    removeSelectedLink,
    removeSelectedNode,
  } = useGraphContext();

  const {
    mode3D,
    modeTree,
    withForces,
    selectFreeRectangle,
    selectFree,
    selectRelationshipMode,
    showTimeRange,
  } = graphState;

  const toggleMode3D = () => {
    setGraphStateProp('mode3D', !mode3D);
  };

  const toggleVerticalTree = () => {
    const isNotVertical = modeTree !== 'td';
    setGraphStateProp('modeTree', isNotVertical ? 'td' : null);
  };

  const toggleHorizontalTree = () => {
    const isNotHorizontal = modeTree !== 'lr';
    setGraphStateProp('modeTree', isNotHorizontal ? 'lr' : null);
  };

  const toggleForces = () => {
    setGraphStateProp('withForces', !withForces);
  };

  const zoomToFit = () => {
    graphRef.current?.zoomToFit(400, 100);
  };

  /**
   * Remove fx and fy positions responsible for fixed positions when
   * mode forces is on and reapply forces.
   */
  const unfixNodes = () => {
    graphData?.nodes.forEach((node) => {
      node.fx = undefined; // eslint-disable-line no-param-reassign
      node.fy = undefined; // eslint-disable-line no-param-reassign
    });
    graphRef.current?.d3ReheatSimulation();
  };

  const toggleSelectFreeRectangle = () => {
    setGraphStateProp('selectFree', false);
    setGraphStateProp('selectFreeRectangle', !selectFreeRectangle);
  };

  const toggleSelectFree = () => {
    setGraphStateProp('selectFreeRectangle', false);
    setGraphStateProp('selectFree', !selectFree);
  };

  const switchSelectRelationshipMode = () => {
    if (selectRelationshipMode === 'children') setGraphStateProp('selectRelationshipMode', 'parent');
    else if (selectRelationshipMode === 'parent') setGraphStateProp('selectRelationshipMode', 'deselect');
    else if (selectRelationshipMode === 'deselect') setGraphStateProp('selectRelationshipMode', null);
    else if (selectRelationshipMode === null) setGraphStateProp('selectRelationshipMode', 'children');
  };

  const toggleTimeRange = () => {
    setGraphStateProp('showTimeRange', !showTimeRange);
  };

  const saveZoom = (z: GraphState['zoom']) => {
    const shouldIgnore = z?.k === 1 && z.x === 0 && z.y === 0;
    if (shouldIgnore) return; // Those zoom values are from graph init, ignore.
    setGraphStateProp('zoom', z);
  };

  /**
   * Select or unselect a node when clicking on it.
   *
   * @param node The node that has been clicked.
   * @param e The event captured.
   */
  const toggleNode: LibGraphProps['onNodeClick'] = (node, e) => {
    const clickedNode = selectedNodes.find((n) => n.id === node.id);
    if (e.ctrlKey || e.shiftKey || e.altKey) {
      if (clickedNode) removeSelectedNode(node);
      else addSelectedNode(node);
    } else {
      setSelectedLinks([]);
      setSelectedNodes([node]);
    }
  };

  /**
   * Select or unselect a link when clicking on it.
   *
   * @param link The link that has been clicked.
   * @param e The event captured.
   */
  const toggleLink: LibGraphProps['onLinkClick'] = (link, e) => {
    const clickedLink = selectedLinks.find((l) => l.id === link.id);
    if (e.ctrlKey || e.shiftKey || e.altKey) {
      if (clickedLink) removeSelectedLink(link);
      else addSelectedLink(link);
    } else {
      setSelectedNodes([]);
      setSelectedLinks([link]);
    }
  };

  /**
   * Move all selected node if the one currently dragged is among them.
   *
   * @param node The dragged node.
   * @param translate How much the dragged node has moved.
   */
  const moveSelection: LibGraphProps['onNodeDrag'] = (node, translate) => {
    const selectedDraggedNode = selectedNodes.find((n) => n.id === node.id);
    if (selectedDraggedNode) {
      selectedNodes.forEach((n) => {
        if (n.id !== node.id) {
          n.x += translate.x; // eslint-disable-line no-param-reassign
          n.y += translate.y; // eslint-disable-line no-param-reassign
          // During node drag, the lib force-graph set fx and fy equal to x and y.
          // so we are doing the same thing for all selected nodes.
          n.fx = n.x; // eslint-disable-line no-param-reassign
          n.fy = n.y; // eslint-disable-line no-param-reassign
        }
      });
    }
  };

  /**
   * Set fx and fy values manually to avoid force-graph to reset them.
   * By fixing those values we avoid nodes to be impacted by forces.
   *
   * @param node The dragged node.
   */
  const fixPositionsOnDragEnd = (node: GraphNode) => {
    const selectedDraggedNode = selectedNodes.find((n) => n.id === node.id);
    node.fx = node.x; // eslint-disable-line no-param-reassign
    node.fy = node.y; // eslint-disable-line no-param-reassign
    if (selectedDraggedNode) {
      selectedNodes.forEach((n) => {
        if (n.id !== node.id) {
          n.fx = n.x; // eslint-disable-line no-param-reassign
          n.fy = n.y; // eslint-disable-line no-param-reassign
        }
      });
    }
  };

  const clearSelection = () => {
    setSelectedNodes([]);
    setSelectedLinks([]);
  };

  /**
   * Determine which nodes are inside the rectangle and select them.
   *
   * @param coords Coordinates of the rectangle.
   * @param keys If special keys has been pressed during draw.
   */
  const selectFromFreeRectangle: RectangleSelectionProps['onSelection'] = (coords, keys) => {
    const { origin, target } = coords;
    const { altKey, shiftKey } = keys;
    const hasSpecialKey = altKey || shiftKey;
    if (!hasSpecialKey) clearSelection();
    const graphOrigin = graphRef.current?.screen2GraphCoords(origin[0], origin[1]);
    const graphTarget = graphRef.current?.screen2GraphCoords(target[0], target[1]);
    if (graphOrigin && graphTarget) {
      const selected = (graphData?.nodes ?? []).filter((node) => {
        return (
          node.x >= graphOrigin.x
          && node.x <= graphTarget.x
          && node.y >= graphOrigin.y
          && node.y <= graphTarget.y
        );
      });
      if (!hasSpecialKey) setSelectedNodes(selected);
      else setSelectedNodes((old) => [...old, ...selected]);
    }
  };

  const selectByEntityType = (entityType: string) => {
    clearSelection();
    const matchingNodes = (graphData?.nodes ?? []).filter(({ entity_type }) => entity_type === entityType);
    setSelectedNodes(matchingNodes);
  };

  const selectAllNodes = () => {
    clearSelection();
    setSelectedNodes(graphData?.nodes ?? []);
  };

  return {
    toggleMode3D,
    toggleVerticalTree,
    toggleHorizontalTree,
    toggleForces,
    toggleSelectFreeRectangle,
    toggleSelectFree,
    switchSelectRelationshipMode,
    toggleTimeRange,
    saveZoom,
    toggleLink,
    toggleNode,
    clearSelection,
    moveSelection,
    fixPositionsOnDragEnd,
    zoomToFit,
    unfixNodes,
    selectFromFreeRectangle,
    selectByEntityType,
    selectAllNodes,
  };
};

export default useGraphInteractions;
