import { useGraphContext, GraphState } from './GraphContext';
import type { GraphNode, LibGraphProps } from '../graph.types';

const useGraphInteractions = () => {
  const {
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
    setGraphStateProp('modeTree', modeTree !== 'td' ? 'td' : null);
  };

  const toggleHorizontalTree = () => {
    setGraphStateProp('modeTree', modeTree !== 'lr' ? 'lr' : null);
  };

  const toggleForces = () => {
    setGraphStateProp('withForces', !withForces);
  };

  const toggleSelectFreeRectangle = () => {
    setGraphStateProp('selectFreeRectangle', !selectFreeRectangle);
  };

  const toggleSelectFree = () => {
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
    if (shouldIgnore) return; // It's zoom values during graph init.
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
  };
};

export default useGraphInteractions;
