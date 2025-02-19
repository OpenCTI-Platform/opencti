import { useEffect } from 'react';
import { NodeObject } from 'react-force-graph-2d';
import { useGraphContext } from '../GraphContext';
import type { GraphNode, LibGraphProps, GraphState } from '../graph.types';
import { RectangleSelectionProps } from '../components/RectangleSelection';
import { getMainRepresentative, getSecondaryRepresentative } from '../../defaultRepresentatives';
import useGraphParser, { ObjectToParse } from './useGraphParser';

const useGraphInteractions = () => {
  const { buildNode, buildLink } = useGraphParser();

  const {
    graphData,
    addNode: contextAddNode,
    removeNode: contextRemoveNode,
    addLink: contextAddLink,
    removeLink: contextRemoveLink,
    graphRef2D,
    graphRef3D,
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
    disabledEntityTypes,
    disabledMarkings,
    disabledCreators,
  } = graphState;

  useEffect(() => {
    setGraphStateProp('selectRelationshipMode', null);
  }, [selectedNodes]);

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
    graphRef2D.current?.zoomToFit(400, 100);
    graphRef3D.current?.zoomToFit(400, 0);
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
    graphRef2D.current?.d3ReheatSimulation();
    graphRef3D.current?.d3ReheatSimulation();
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
    const selectedNodesIds = selectedNodes.map((n) => n.id);
    setSelectedLinks((graphData?.links ?? []).filter((l) => {
      const shouldGetFrom = selectRelationshipMode === null || selectRelationshipMode === 'children';
      const shouldGetTo = selectRelationshipMode === null || selectRelationshipMode === 'parent';
      return (shouldGetFrom && selectedNodesIds.includes(l.source_id))
        || (shouldGetTo && selectedNodesIds.includes(l.target_id));
    }));

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
  const moveSelection = (
    node: NodeObject<GraphNode>,
    translate: { x: number, y: number, z?: number },
  ) => {
    const selectedDraggedNode = selectedNodes.find((n) => n.id === node.id);
    if (selectedDraggedNode) {
      selectedNodes.forEach((n) => {
        if (n.id !== node.id) {
          n.x += translate.x; // eslint-disable-line no-param-reassign
          n.y += translate.y; // eslint-disable-line no-param-reassign
          n.z += translate.z ?? 0; // eslint-disable-line no-param-reassign
          // During node drag, the lib force-graph set fx and fy equal to x and y.
          // so we are doing the same thing for all selected nodes.
          n.fx = n.x; // eslint-disable-line no-param-reassign
          n.fy = n.y; // eslint-disable-line no-param-reassign
          n.fz = n.z; // eslint-disable-line no-param-reassign
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
    node.fz = node.z; // eslint-disable-line no-param-reassign
    if (selectedDraggedNode) {
      selectedNodes.forEach((n) => {
        if (n.id !== node.id) {
          n.fx = n.x; // eslint-disable-line no-param-reassign
          n.fy = n.y; // eslint-disable-line no-param-reassign
          n.fz = n.z; // eslint-disable-line no-param-reassign
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
    const graphOrigin = graphRef2D.current?.screen2GraphCoords(origin[0], origin[1]);
    const graphTarget = graphRef2D.current?.screen2GraphCoords(target[0], target[1]);
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

  const selectBySearch = (search: string) => {
    clearSelection();
    if (search) {
      const searchLow = search.toLowerCase();
      const matchingNodes = (graphData?.nodes ?? []).filter((node) => {
        return (getMainRepresentative(node) || '').toLowerCase().indexOf(searchLow) !== -1
          || (getSecondaryRepresentative(node) || '').toLowerCase().indexOf(searchLow) !== -1
          || (node.entity_type || '').toLowerCase().indexOf(searchLow) !== -1;
      });
      setSelectedNodes(matchingNodes);
    }
  };

  const toggleEntityType = (type: string) => {
    setGraphStateProp(
      'disabledEntityTypes',
      disabledEntityTypes.includes(type)
        ? disabledEntityTypes.filter((t) => t !== type)
        : [...disabledEntityTypes, type],
    );
  };

  const toggleMarkingDefinition = (markingId: string) => {
    setGraphStateProp(
      'disabledMarkings',
      disabledMarkings.includes(markingId)
        ? disabledMarkings.filter((id) => id !== markingId)
        : [...disabledMarkings, markingId],
    );
  };

  const toggleCreator = (creatorId: string) => {
    setGraphStateProp(
      'disabledCreators',
      disabledCreators.includes(creatorId)
        ? disabledCreators.filter((id) => id !== creatorId)
        : [...disabledCreators, creatorId],
    );
  };

  const resetFilters = () => {
    setGraphStateProp('disabledEntityTypes', []);
    setGraphStateProp('disabledMarkings', []);
    setGraphStateProp('disabledCreators', []);
  };

  const addNode = (data: ObjectToParse) => {
    contextAddNode(buildNode(data, {}));
    setTimeout(() => zoomToFit(), 200); // To refresh graph.
  };

  const removeNode = (nodeId: string) => {
    contextRemoveNode(nodeId);
    setTimeout(() => zoomToFit(), 200); // To refresh graph.
  };

  const addLink = (data: ObjectToParse) => {
    contextAddLink(buildLink(data)); // TODO does it work with nested?
    setTimeout(() => zoomToFit(), 200); // To refresh graph.
  };

  const removeLink = (linkId: string) => {
    contextRemoveLink(linkId);
    setTimeout(() => zoomToFit(), 200); // To refresh graph.
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
    toggleEntityType,
    toggleMarkingDefinition,
    toggleCreator,
    resetFilters,
    selectBySearch,
    addNode,
    removeNode,
    addLink,
    removeLink,
  };
};

export default useGraphInteractions;
