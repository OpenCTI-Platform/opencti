import { NodeObject } from 'react-force-graph-2d';
import { useGraphContext } from '../GraphContext';
import { GraphNode, LibGraphProps, GraphState, GraphLink } from '../graph.types';
import { RectangleSelectionProps } from '../components/RectangleSelection';
import { getMainRepresentative, getSecondaryRepresentative } from '../../../utils/defaultRepresentatives';
import useGraphParser, { ObjectToParse } from './useGraphParser';

const useGraphInteractions = () => {
  const {
    buildNode,
    buildLink,
    buildCorrelationData,
    buildGraphData,
  } = useGraphParser();

  const {
    graphRef2D,
    graphRef3D,
    graphData,
    graphState,
    rawPositions,
    rawObjects,
    setGraphData,
    setGraphState,
    setRawPositions,
    setRawObjects,
    context,
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
    selectedLinks,
    selectedNodes,
  } = graphState;

  /**
   * Internal function to easily modify one property in the state.
   *
   * @param key Name of the property to change.
   * @param value New value for the property.
   */
  const setGraphStateProp = <K extends keyof GraphState>(key: K, value: GraphState[K]) => {
    setGraphState((oldState) => {
      return { ...oldState, [key]: value };
    });
  };

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

  const selectDetailsPreviewObject = (object: GraphNode | GraphLink) => {
    setGraphStateProp('detailsPreviewSelected', object);
  };

  const zoomToFit = () => {
    const nbOfNodes = graphData?.nodes.length ?? 0;
    let padding = 50;
    if (nbOfNodes === 1) {
      if (window.innerHeight < 600) {
        padding = 50;
      } else if (window.innerHeight < 900) {
        padding = 150;
      } else if (window.innerHeight < 1100) {
        padding = 300;
      } else {
        padding = 400;
      }
    } else if (nbOfNodes < 4) padding = 200;
    else if (nbOfNodes < 8) padding = 100;
    // Different padding depending on the number of nodes in the graph.
    graphRef2D.current?.zoomToFit(400, padding);
    graphRef3D.current?.zoomToFit(400, padding);
  };

  const setZoom = (zoomLevel: NonNullable<GraphState['zoom']>) => {
    graphRef2D.current?.zoom(zoomLevel.k, 400);
    graphRef2D.current?.centerAt(zoomLevel.x, zoomLevel.y, 400);
  };

  /**
   * Configure the forces of the lib react-force-graph.
   * Those values are the ones taken from previous version of graphs.
   */
  const initForces = () => {
    if (modeTree) {
      graphRef2D.current?.d3Force('charge')?.strength(-1000);
      graphRef3D.current?.d3Force('charge')?.strength(-1000);
    } else {
      graphRef2D.current?.d3Force('link')?.distance(50);
      graphRef3D.current?.d3Force('link')?.distance(50);
    }
  };

  const applyForces = () => {
    graphRef2D.current?.d3ReheatSimulation();
    graphRef3D.current?.d3ReheatSimulation();
  };

  const toggleSelectFreeRectangle = () => {
    setGraphStateProp('selectFree', false);
    setGraphStateProp('selectFreeRectangle', !selectFreeRectangle);
  };

  const setSelectedTimeRange = (range: [Date, Date]) => {
    setGraphStateProp('selectedTimeRangeInterval', range);
  };

  const toggleSelectFree = () => {
    setGraphStateProp('selectFreeRectangle', false);
    setGraphStateProp('selectFree', !selectFree);
  };

  const setSelectedLinks = (links: GraphLink[]) => {
    setGraphStateProp('selectedLinks', links);
  };

  const setSelectedNodes = (nodes: GraphNode[]) => {
    setGraphStateProp('selectedNodes', nodes);
  };

  const setLinearProgress = (val: boolean) => {
    setGraphStateProp('showLinearProgress', val);
  };

  const setLoadingTotal = (val: number) => {
    setGraphStateProp('loadingTotal', val);
  };

  const setLoadingCurrent = (val: number) => {
    setGraphStateProp('loadingCurrent', val);
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

  const setCorrelationMode = (mode: GraphState['correlationMode']) => {
    setGraphStateProp('correlationMode', mode);
  };

  const toggleTimeRange = () => {
    setGraphStateProp('showTimeRange', !showTimeRange);
  };

  const saveZoom = (z: GraphState['zoom']) => {
    const shouldIgnore = !z || (z.x === 0 && z.y === 0);
    if (shouldIgnore) return; // Those zoom values are from graph init, ignore.
    setGraphStateProp('zoom', z);
  };

  const addSelectedLink = (link: GraphLink) => {
    const existing = selectedLinks.find((l) => l.id === link.id);
    if (!existing) setSelectedLinks([...selectedLinks, link]);
  };

  const removeSelectedLink = (link: GraphLink) => {
    setSelectedLinks(selectedLinks.filter((l) => l.id !== link.id));
  };

  const addSelectedNode = (node: GraphNode) => {
    const existing = selectedNodes.find((n) => n.id === node.id);
    if (!existing) setSelectedNodes([...selectedNodes, node]);
  };

  const removeSelectedNode = (node: GraphNode) => {
    setSelectedNodes(selectedNodes.filter((n) => n.id !== node.id));
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
    translate: { x: number; y: number; z?: number },
  ) => {
    const selectedDraggedNode = selectedNodes.find((n) => n.id === node.id);
    if (selectedDraggedNode) {
      selectedNodes.forEach((n) => {
        if (n.id !== node.id) {
          n.x += translate.x;
          n.y += translate.y;
          n.z += translate.z ?? 0;
          // During node drag, the lib force-graph set fx and fy equal to x and y.
          // so we are doing the same thing for all selected nodes.
          n.fx = n.x;
          n.fy = n.y;
          n.fz = n.z;
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
    node.fx = node.x;
    node.fy = node.y;
    node.fz = node.z;
    if (selectedDraggedNode) {
      selectedNodes.forEach((n) => {
        if (n.id !== node.id) {
          n.fx = n.x;
          n.fy = n.y;
          n.fz = n.z;
        }
      });
    }
  };

  const clearSelection = () => {
    setSelectedNodes([]);
    setSelectedLinks([]);
    setGraphStateProp('search', undefined);
    setGraphStateProp('detailsPreviewSelected', undefined);
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
      else setSelectedNodes([...selectedNodes, ...selected]);
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
    setGraphStateProp('search', search);
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
    setGraphStateProp('selectedTimeRangeInterval', undefined);
  };

  const rebuildGraphData = (objects: ObjectToParse[], resetPositions = false) => {
    const filteredObjects = context === 'correlation' && graphState.correlationMode === 'observables'
      ? objects.filter((o) => (
          o.entity_type === 'Indicator' || o.parent_types.includes('Stix-Cyber-Observable')
        ))
      : objects;
    setRawObjects(filteredObjects);
    setGraphData(context === 'correlation'
      ? buildCorrelationData(filteredObjects, resetPositions ? {} : rawPositions)
      : buildGraphData(filteredObjects, resetPositions ? {} : rawPositions));
  };

  /**
   * Remove fx and fy positions responsible for fixed positions when
   * mode forces is on and reapply forces.
   */
  const unfixNodes = () => {
    // --- Alternative way of unfixing nodes, not used for now.
    // graphData?.nodes.forEach((node) => {
    //   node.fx = undefined; // eslint-disable-line no-param-reassign
    //   node.fy = undefined; // eslint-disable-line no-param-reassign
    // });
    // applyForces();
    // --- Hard way of unfixing nodes, chosen one for now.
    rebuildGraphData(rawObjects, true);
    applyForces();
  };

  const updateNode = (data: ObjectToParse) => {
    const nodes = rawObjects.filter((o) => o.id !== data.id);
    if (rawObjects.length === nodes.length) return;
    const newNodes = [...nodes, data];
    rebuildGraphData(newNodes);
  };

  const addNode = (data: ObjectToParse) => {
    if (rawObjects.find((o) => o.id === data.id)) {
      return;
    }
    setRawObjects((old) => ([...old, data]));
    const node = buildNode(data, rawPositions);
    setGraphData((oldData) => {
      const withoutExisting = (oldData?.nodes ?? []).filter((n) => n.id !== node.id);
      return {
        nodes: [...withoutExisting, node],
        links: oldData?.links ?? [],
      };
    });
  };

  const removeNode = (nodeId: string) => {
    setRawObjects((old) => old.filter((o) => o.id !== nodeId));
    setGraphData((oldData) => {
      return {
        nodes: (oldData?.nodes ?? []).filter((node) => node.id !== nodeId),
        links: oldData?.links ?? [],
      };
    });
  };

  const removeNodes = (nodeIds: string[]) => {
    setRawObjects((old) => old.filter((o) => !nodeIds.includes(o.id)));
    setGraphData((oldData) => {
      return {
        nodes: (oldData?.nodes ?? []).filter((node) => !nodeIds.includes(node.id)),
        links: oldData?.links ?? [],
      };
    });
  };

  const addLink = (data: ObjectToParse) => {
    if (!rawObjects.find((o) => o.id === data.id)) {
      setRawObjects((old) => ([...old, data]));
    }
    const link = buildLink(data); // TODO does it work with nested?
    setGraphData((oldData) => {
      const withoutExisting = (oldData?.links ?? []).filter((l) => l.id !== link.id);
      return {
        links: [...withoutExisting, link],
        nodes: oldData?.nodes ?? [],
      };
    });
  };

  const removeLink = (linkId: string) => {
    setRawObjects((old) => old.filter((o) => o.id !== linkId));
    setGraphData((oldData) => {
      return {
        links: (oldData?.links ?? []).filter((link) => link.id !== linkId),
        nodes: oldData?.nodes ?? [],
      };
    });
  };

  const removeLinks = (linkIds: string[]) => {
    setRawObjects((old) => old.filter((o) => !linkIds.includes(o.id)));
    setGraphData((oldData) => {
      return {
        links: (oldData?.links ?? []).filter((link) => !linkIds.includes(link.id)),
        nodes: oldData?.nodes ?? [],
      };
    });
  };

  const setIsAddRelationOpen = (val: boolean) => {
    setGraphStateProp('isAddRelationOpen', val);
  };

  const setIsExpandOpen = (val: boolean) => {
    setGraphStateProp('isExpandOpen', val);
  };

  return {
    toggleMode3D,
    toggleVerticalTree,
    toggleHorizontalTree,
    toggleForces,
    toggleSelectFreeRectangle,
    toggleSelectFree,
    switchSelectRelationshipMode,
    setCorrelationMode,
    toggleTimeRange,
    saveZoom,
    setSelectedLinks,
    setSelectedNodes,
    toggleLink,
    toggleNode,
    selectDetailsPreviewObject,
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
    applyForces,
    initForces,
    removeNode,
    removeNodes,
    addLink,
    removeLink,
    removeLinks,
    setSelectedTimeRange,
    setIsAddRelationOpen,
    setRawPositions,
    setLinearProgress,
    rebuildGraphData,
    setLoadingTotal,
    setLoadingCurrent,
    setZoom,
    setIsExpandOpen,
    updateNode,
  };
};

export default useGraphInteractions;
