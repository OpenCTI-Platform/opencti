import { NodeObject } from 'react-force-graph-2d';
import { useGraphContext } from '../GraphContext';
import { GraphNode, LibGraphProps, GraphState, GraphLink, GraphLayoutMode } from '../graph.types';
import { RectangleSelectionProps } from '../components/RectangleSelection';
import { getMainRepresentative, getSecondaryRepresentative } from '../../../utils/defaultRepresentatives';
import useGraphParser, { ObjectToParse } from './useGraphParser';
import { collisionForce } from './collisionForce';
import { neighbourhood, shortestPath } from './graphFocus';
import { createCollapseCache, isCollapsedMember, isGroupLink, withCollapsedGroups } from './graphCollapse';
import { frameBox, measureGraphPanels } from './graphFraming';

/** Graph units between two linked nodes at rest, room for a label between two rings. */
const LINK_DISTANCE = 64;
const CHARGE_STRENGTH = -120;
/** Two nodes are kept this far apart, centre to centre, so neither discs nor labels overlap. */
const COLLISION_DISTANCE = 22;
const ZOOM_STEP = 1.4;
const ZOOM_MS = 300;
const MIN_LOCATE_ZOOM = 2.5;
/** Fitting a few nodes never zooms in further: a single node then reads at a comfortable size. */
const MAX_FIT_ZOOM = 6;

const endpointId = (end: GraphLink['source']) => (typeof end === 'object' && end !== null ? end.id : end);

const useGraphInteractions = () => {
  const {
    buildNode,
    buildLink,
    buildCorrelationData,
    buildGraphData,
    buildGraphDataAfterRelationshipLinkToNodeConversion,
  } = useGraphParser();

  const {
    graphRef2D,
    graphRef3D,
    viewportRef,
    toolbarRef,
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
    selectedNodes,
    selectedLinks,
    layoutMode,
    hiddenNodeIds = [],
    collapsedEntityTypes = [],
    disabledRelationshipTypes = [],
    showLegend = true,
  } = graphState;

  /** Whether the reader can see and pick the node: neither hidden nor folded into a group. */
  const isNodeShown = (node: GraphNode) => !hiddenNodeIds.includes(node.id)
    && !isCollapsedMember(node, collapsedEntityTypes);

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
    if (isNotVertical) setGraphStateProp('layoutMode', null);
  };

  const toggleHorizontalTree = () => {
    const isNotHorizontal = modeTree !== 'lr';
    setGraphStateProp('modeTree', isNotHorizontal ? 'lr' : null);
    if (isNotHorizontal) setGraphStateProp('layoutMode', null);
  };

  /**
   * Switches a deterministic layout on or off; one layout at a time, so the tree modes go off.
   * The radial layout is centred on the first selected node when there is one.
   */
  const toggleLayoutMode = (mode: GraphLayoutMode) => {
    const enabling = layoutMode !== mode;
    setGraphStateProp('layoutMode', enabling ? mode : null);
    if (enabling) setGraphStateProp('modeTree', null);
    if (mode === 'radial') setGraphStateProp('layoutCentreId', enabling ? (selectedNodes[0]?.id ?? null) : null);
  };

  const centreRadialLayoutOn = (nodeId: string) => {
    setGraphStateProp('modeTree', null);
    setGraphStateProp('layoutMode', 'radial');
    setGraphStateProp('layoutCentreId', nodeId);
  };

  const toggleLegend = () => {
    setGraphStateProp('showLegend', !showLegend);
  };

  /** Whether the link has an end among the given nodes. */
  const touches = (link: GraphLink, isGone: (nodeId: string) => boolean) => [
    endpointId(link.source) ?? link.source_id,
    endpointId(link.target) ?? link.target_id,
  ].some((nodeId) => !!nodeId && isGone(nodeId));

  const hideNodes = (nodeIds: string[]) => {
    if (nodeIds.length === 0) return;
    setGraphStateProp('hiddenNodeIds', [...new Set([...hiddenNodeIds, ...nodeIds])]);
    setGraphStateProp('selectedNodes', selectedNodes.filter((n) => !nodeIds.includes(n.id)));
    // The relationships of a hidden entity are no longer drawn: they leave the selection with it.
    setGraphStateProp('selectedLinks', selectedLinks.filter((link) => !touches(link, (id) => nodeIds.includes(id))));
  };

  const showHiddenNodes = () => {
    setGraphStateProp('hiddenNodeIds', []);
  };

  const toggleCollapsedEntityType = (type: string) => {
    const collapsing = !collapsedEntityTypes.includes(type);
    setGraphStateProp(
      'collapsedEntityTypes',
      collapsing ? [...collapsedEntityTypes, type] : collapsedEntityTypes.filter((t) => t !== type),
    );
    if (collapsing) {
      const members = new Set((graphData?.nodes ?? []).filter((n) => isCollapsedMember(n, [type])).map((n) => n.id));
      setGraphStateProp('selectedNodes', selectedNodes.filter((n) => !members.has(n.id)));
      // The relationships of the members are drawn towards their group: they leave the selection too.
      setGraphStateProp('selectedLinks', selectedLinks.filter((link) => !touches(link, (id) => members.has(id))));
    }
  };

  const toggleRelationshipType = (type: string) => {
    setGraphStateProp(
      'disabledRelationshipTypes',
      disabledRelationshipTypes.includes(type)
        ? disabledRelationshipTypes.filter((t) => t !== type)
        : [...disabledRelationshipTypes, type],
    );
  };

  /**
   * Links the reader can see, by their two end ids: neither end hidden or faded by a filter, and the links of the members
   * of a collapsed type drawn towards their group, as the canvas draws them.
   */
  const shownLinkEnds = () => {
    const drawn = graphData
      ? withCollapsedGroups(graphData, collapsedEntityTypes, () => '', createCollapseCache(), new Set(hiddenNodeIds))
      : graphData;
    const shownIds = new Set((drawn?.nodes ?? []).filter((n) => isNodeShown(n) && !n.disabled).map((n) => n.id));
    return (drawn?.links ?? []).flatMap((link) => {
      const sourceId = endpointId(link.source) ?? link.source_id;
      const targetId = endpointId(link.target) ?? link.target_id;
      if (link.disabled || !shownIds.has(sourceId) || !shownIds.has(targetId)) return [];
      return [{ id: link.id, sourceId, targetId }];
    });
  };

  /**
   * Highlights the shortest path between the two selected nodes, whatever the direction of the
   * relationships. Returns `false` when they are not connected by what is drawn.
   */
  const highlightShortestPath = (fromId?: string, toId?: string): boolean => {
    const ends = fromId && toId ? [fromId, toId] : selectedNodes.map((n) => n.id);
    if (ends.length !== 2) return false;
    const path = shortestPath(shownLinkEnds(), ends[0], ends[1]);
    setGraphStateProp('highlightedPath', path);
    return path !== null;
  };

  const clearHighlightedPath = () => {
    setGraphStateProp('highlightedPath', null);
  };

  /** Selects the given nodes (the selection by default) and every node one relationship away. */
  const selectNeighbours = (centreIds?: string[]) => {
    const { nodeIds } = neighbourhood(shownLinkEnds(), centreIds ?? selectedNodes.map((n) => n.id));
    setGraphStateProp('selectedLinks', []);
    setGraphStateProp('selectedNodes', (graphData?.nodes ?? []).filter((n) => nodeIds.has(n.id)));
  };

  const zoomBy = (factor: number) => {
    const graph = graphRef2D.current;
    if (graph) graph.zoom(graph.zoom() * factor, ZOOM_MS);
  };
  const zoomIn = () => zoomBy(ZOOM_STEP);
  const zoomOut = () => zoomBy(1 / ZOOM_STEP);

  /**
   * Frames the 2D nodes kept by `filter`, all of them by default, clear of the panels floating
   * over the canvas. False when there is nothing to frame yet.
   */
  const frameNodes = (padding: number, duration: number, filter?: (node: NodeObject<GraphNode>) => boolean) => {
    const graph = graphRef2D.current;
    const viewport = viewportRef.current;
    const canvas = viewport?.querySelector('canvas');
    if (!graph || !viewport || !canvas) return false;
    const box = graph.getGraphBbox(filter);
    if (!box || !Number.isFinite(box.x[0]) || !Number.isFinite(box.y[0])) return false;
    const { width, height } = canvas.getBoundingClientRect();
    const frame = frameBox(box, { width, height }, measureGraphPanels(viewport, canvas, [toolbarRef.current]), { padding, maxZoom: MAX_FIT_ZOOM });
    graph.centerAt(frame.x, frame.y, duration);
    graph.zoom(frame.k, duration);
    return true;
  };

  /** Frames the selected nodes, or the given ones. */
  const zoomToSelection = (nodeIds?: string[]) => {
    const ids = new Set(nodeIds ?? selectedNodes.map((n) => n.id));
    if (ids.size === 0) return;
    const padding = ids.size === 1 ? 200 : 80;
    if (!frameNodes(padding, ZOOM_MS * 1.5, (node) => ids.has(String(node.id)))) {
      graphRef2D.current?.zoomToFit(ZOOM_MS * 1.5, padding, (node) => ids.has(String(node.id)));
    }
    graphRef3D.current?.zoomToFit(ZOOM_MS * 1.5, padding, (node) => ids.has(String(node.id)));
  };

  /** Centres the view on a node (the first selected one by default), zooming in when far out. */
  const locateNode = (nodeId?: string) => {
    const id = nodeId ?? selectedNodes[0]?.id;
    const node = (graphData?.nodes ?? []).find((n) => n.id === id);
    const graph = graphRef2D.current;
    if (!node || !graph) return;
    graph.centerAt(node.x, node.y, ZOOM_MS);
    if (graph.zoom() < MIN_LOCATE_ZOOM) graph.zoom(MIN_LOCATE_ZOOM, ZOOM_MS);
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
    if (!frameNodes(padding, 400)) graphRef2D.current?.zoomToFit(400, padding);
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
      graphRef2D.current?.d3Force('link')?.distance(LINK_DISTANCE);
      graphRef2D.current?.d3Force('charge')?.strength(CHARGE_STRENGTH);
      graphRef3D.current?.d3Force('link')?.distance(50);
    }
    // Keeps the rings and the labels under them apart, which the repulsion alone does not.
    graphRef2D.current?.d3Force('collide', collisionForce(COLLISION_DISTANCE));
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

  // Group links are never selected: the edition and removal of the selection act on its ids.
  const setSelectedLinks = (links: GraphLink[]) => {
    setGraphStateProp('selectedLinks', links.filter((link) => !isGroupLink(link)));
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
    // Only what is drawn can be selected: never a relationship towards a hidden or collapsed entity.
    const shownIds = new Set((graphData?.nodes ?? []).filter(isNodeShown).map((n) => n.id));
    setSelectedLinks((graphData?.links ?? []).filter((l) => {
      if (!shownIds.has(l.source_id) || !shownIds.has(l.target_id)) return false;
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

  // The additive selection reads the selection of the latest state: the click handlers the
  // rendering library holds can date from the render before a previous click.
  const toggleInSelection = (key: 'selectedNodes' | 'selectedLinks', element: GraphNode | GraphLink) => {
    if (key === 'selectedLinks' && isGroupLink(element)) return;
    setGraphState((oldState) => {
      const current = (oldState[key] ?? []) as (GraphNode | GraphLink)[];
      const next = current.some((e) => e.id === element.id) ? current.filter((e) => e.id !== element.id) : [...current, element];
      return { ...oldState, [key]: next };
    });
  };

  /**
   * Select or unselect a node when clicking on it.
   *
   * @param node The node that has been clicked.
   * @param e The event captured.
   */
  const toggleNode: LibGraphProps['onNodeClick'] = (node, e) => {
    if (e.ctrlKey || e.shiftKey || e.altKey) {
      toggleInSelection('selectedNodes', node);
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
    if (isGroupLink(link)) return;
    if (e.ctrlKey || e.shiftKey || e.altKey) {
      toggleInSelection('selectedLinks', link);
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
    setGraphStateProp('highlightedPath', null);
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
        return isNodeShown(node) && (
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
    const matchingNodes = (graphData?.nodes ?? []).filter((node) => node.entity_type === entityType && isNodeShown(node));
    setSelectedNodes(matchingNodes);
  };

  const selectAllNodes = () => {
    clearSelection();
    setSelectedNodes((graphData?.nodes ?? []).filter(isNodeShown));
  };

  const selectBySearch = (search: string) => {
    clearSelection();
    setGraphStateProp('search', search);
    if (search) {
      const searchLow = search.toLowerCase();
      const matchingNodes = (graphData?.nodes ?? []).filter(isNodeShown).filter((node) => {
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
    setGraphStateProp('disabledRelationshipTypes', []);
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
    // A tree, tier or radial layout would pin the nodes again, and the positions saved in memory
    // would come back when it is switched off: both are left before the forces are reapplied.
    setGraphStateProp('layoutMode', null);
    setGraphStateProp('modeTree', null);
    setRawPositions({});
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
    setGraphData((oldData) => {
      let newGraphData = oldData;
      // If the from or the to of the link to add is a relationship displayed as a link
      // add it as a node so the link to add can be drawn properly.
      if (data.from?.relationship_type) {
        newGraphData = buildGraphDataAfterRelationshipLinkToNodeConversion(newGraphData, rawObjects, rawPositions, data.from);
      }
      if (data.to?.relationship_type) {
        newGraphData = buildGraphDataAfterRelationshipLinkToNodeConversion(newGraphData, rawObjects, rawPositions, data.to);
      }
      // link to add
      const link = buildLink(data);
      const withoutExisting = (newGraphData?.links ?? []).filter((l) => l.id !== link.id);
      const newLinks = [...withoutExisting, link];
      const newNodes = newGraphData?.nodes ?? [];
      // set the new links and nodes
      return { links: newLinks, nodes: newNodes };
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
    isNodeShown,
    toggleLayoutMode,
    centreRadialLayoutOn,
    toggleLegend,
    hideNodes,
    showHiddenNodes,
    toggleCollapsedEntityType,
    toggleRelationshipType,
    highlightShortestPath,
    clearHighlightedPath,
    selectNeighbours,
    zoomIn,
    zoomOut,
    zoomToSelection,
    frameNodes,
    locateNode,
  };
};

export default useGraphInteractions;
