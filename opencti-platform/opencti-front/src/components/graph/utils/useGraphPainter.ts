import { useMemo, useRef } from 'react';
import { useTheme } from '@mui/material/styles';
import SpriteText from 'three-spritetext';
import { ForceGraphProps } from 'react-force-graph-3d';
import type { Theme } from '../../Theme';
import type { GraphLink, GraphNode } from '../graph.types';
import { useFormatter } from '../../i18n';
import { buildGraphPalette } from './graphPalette';
import { type Box, computeLinkCurvatures, computeObstacleBends, type LinkEnds, linkEndsKey } from './graphGeometry';
import type { LayoutPositions } from './graphLayouts';
import { type GraphFocus, type GraphPath, neighbourhood } from './graphFocus';
import {
  type LevelOfDetail,
  levelOfDetail,
  type LinkLabel,
  type LinkPaintOptions,
  NODE_RADIUS,
  paintGraphLink,
  paintGraphNode,
  paintGraphNodeHitArea,
  paintLinkLabels,
} from './graphPainting';
import { badgesOfNode, type GraphBadge, useGraphBadgeRegistryVersion } from '../badges';

interface PaintOptions {
  showNbConnectedElements?: boolean;
  /** Zoom level handed by the rendering library; fixes the level of detail. */
  globalScale?: number;
}

export interface GraphHoverTarget {
  kind: 'node' | 'link';
  id: string;
  /** The ends of a link: the two connectors of a nested relationship share its id. */
  sourceId?: string;
  targetId?: string;
}

interface UseGraphPainterArgs {
  selectedLinks: GraphLink[];
  selectedNodes: GraphNode[];
  detailsPreviewSelected: GraphLink | GraphNode | undefined;
  search: string | undefined;
  /** Links drawn, for the focus on a neighbourhood and the fan-out of parallel links. */
  links?: readonly GraphLink[];
  hovered?: GraphHoverTarget | null;
  highlightedPath?: GraphPath | null;
  nodeCount?: number;
  /** Where a deterministic layout puts the nodes: straight links then bend around the nodes on their way. */
  layoutTargets?: LayoutPositions | null;
}

/** Room kept between a bent link and a node it passes: the ring, its halo and a little air. */
const OBSTACLE_CLEARANCE = NODE_RADIUS + 5;

/** A zoom where every detail shows, for callers that do not hand one. */
const DEFAULT_SCALE = 3;

const STRAIGHT_LINK = { curvature: 0, rotation: 0 };

const endpointId = (end: GraphLink['source']) => (typeof end === 'object' && end !== null ? end.id : end);

const linkEndsOf = (link: GraphLink): LinkEnds => ({
  id: link.id,
  sourceId: endpointId(link.source) ?? link.source_id,
  targetId: endpointId(link.target) ?? link.target_id,
});

/** The hover target of a link, telling apart the connectors that share the id of their relationship. */
export const linkHoverTarget = (link: GraphLink): GraphHoverTarget => ({ kind: 'link', ...linkEndsOf(link) });

/** Whether the hover target designates this link, by its id and, when the target has them, its ends. */
export const isHoveredLink = (
  hovered: GraphHoverTarget | null | undefined,
  link: { id: string; sourceId?: string; targetId?: string },
) => hovered?.kind === 'link'
  && hovered.id === link.id
  && (hovered.sourceId === undefined || hovered.sourceId === link.sourceId)
  && (hovered.targetId === undefined || hovered.targetId === link.targetId);

const useGraphPainter = (args?: UseGraphPainterArgs) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const badgeRegistryVersion = useGraphBadgeRegistryVersion();
  const {
    selectedLinks = [],
    selectedNodes = [],
    detailsPreviewSelected,
    search,
    links = [],
    hovered = null,
    highlightedPath = null,
    nodeCount = 0,
    layoutTargets = null,
  } = args ?? {};

  const palette = useMemo(() => buildGraphPalette(theme), [theme]);
  const colors = {
    selected: palette.accent,
    inferred: palette.inferred,
    disabled: palette.disabled,
  };

  const linkEnds = useMemo(() => links.map(linkEndsOf), [links]);
  // The ends and the key of each link drawn, computed once per graph rather than at every frame.
  const linkEndsByLink = useMemo(() => new Map(links.map((link, index) => [link, linkEnds[index]])), [links, linkEnds]);
  const linkKeys = useMemo(() => new Map(links.map((link, index) => [link, linkEndsKey(linkEnds[index])])), [links, linkEnds]);
  const endsOf = (link: GraphLink) => linkEndsByLink.get(link) ?? linkEndsOf(link);
  const keyOf = (link: GraphLink) => linkKeys.get(link) ?? linkEndsKey(endsOf(link));
  const curvatures = useMemo(() => computeLinkCurvatures(linkEnds), [linkEnds]);
  const bends = useMemo(
    () => (layoutTargets ? computeObstacleBends(linkEnds, layoutTargets, OBSTACLE_CLEARANCE, curvatures) : null),
    [layoutTargets, linkEnds, curvatures],
  );

  const selectedNodeIds = useMemo(() => new Set(selectedNodes.map((n) => n.id)), [selectedNodes]);
  const selectedLinkIds = useMemo(() => new Set(selectedLinks.map((l) => l.id)), [selectedLinks]);
  const pathNodeIds = useMemo(() => new Set(highlightedPath?.nodeIds ?? []), [highlightedPath]);
  const pathLinkKeys = useMemo(() => new Set(highlightedPath?.linkKeys ?? []), [highlightedPath]);

  /**
   * What stays at full strength: a highlighted path alone, otherwise the selection and the hovered
   * element with their direct neighbours. `null` when nothing is focused, so nothing fades.
   */
  const focus = useMemo<GraphFocus | null>(() => {
    if (highlightedPath && highlightedPath.nodeIds.length > 0) {
      return { nodeIds: pathNodeIds, linkKeys: pathLinkKeys };
    }
    const centres = new Set(selectedNodeIds);
    selectedLinks.forEach((link) => {
      centres.add(endpointId(link.source) ?? link.source_id);
      centres.add(endpointId(link.target) ?? link.target_id);
    });
    if (hovered?.kind === 'node') centres.add(hovered.id);
    if (hovered?.kind === 'link') {
      const link = linkEnds.find((ends) => isHoveredLink(hovered, ends));
      if (link) {
        centres.add(link.sourceId);
        centres.add(link.targetId);
      }
    }
    if (centres.size === 0) return null;
    const reached = neighbourhood(linkEnds, centres);
    const linkKeys = new Set(reached.linkKeys);
    // A selected relationship is drawn selected on each of its links; the hovered link alone.
    linkEnds.forEach((ends) => {
      if (selectedLinkIds.has(ends.id) || isHoveredLink(hovered, ends)) linkKeys.add(linkEndsKey(ends));
    });
    return { nodeIds: reached.nodeIds, linkKeys };
  }, [highlightedPath, selectedNodeIds, selectedLinks, hovered, linkEnds, pathNodeIds, pathLinkKeys, selectedLinkIds]);

  const typeLabels = useRef(new Map<string, string>());
  const typeLabel = (node: GraphNode) => {
    const key = node.relationship_type ? `relationship_${node.relationship_type}` : `entity_${node.entity_type}`;
    let label = typeLabels.current.get(key);
    if (label === undefined) {
      label = t_i18n(key);
      typeLabels.current.set(key, label);
    }
    return label;
  };

  const badgeCache = useRef(new WeakMap<GraphNode, { version: number; badges: GraphBadge[] }>());
  const badgesOf = (node: GraphNode) => {
    const cached = badgeCache.current.get(node);
    if (cached && cached.version === badgeRegistryVersion) return cached.badges;
    const badges = badgesOfNode(node, { t_i18n });
    badgeCache.current.set(node, { version: badgeRegistryVersion, badges });
    return badges;
  };

  // Computed again only when the zoom or the size of the graph changes, not for every element of every frame
  const detailCache = useRef<{ globalScale: number; nodeCount: number; detail: LevelOfDetail } | null>(null);
  const detailOf = (globalScale: number): LevelOfDetail => {
    const cached = detailCache.current;
    if (cached && cached.globalScale === globalScale && cached.nodeCount === nodeCount) return cached.detail;
    const detail = levelOfDetail(globalScale, nodeCount);
    detailCache.current = { globalScale, nodeCount, detail };
    return detail;
  };

  /**
   * Draws a node in canvas.
   *
   * @param data Data associated to the node.
   * @param ctx Context of the canvas.
   * @param opts Options to change drawing.
   */
  const nodePaint = (
    data: GraphNode,
    ctx: CanvasRenderingContext2D,
    opts: PaintOptions = {},
  ) => {
    const globalScale = opts.globalScale ?? DEFAULT_SCALE;
    const detail = detailOf(globalScale);
    const covered = paintGraphNode(ctx, data, {
      palette,
      globalScale,
      detail,
      visual: {
        selected: selectedNodeIds.has(data.id),
        preview: detailsPreviewSelected?.id === data.id,
        hovered: hovered?.kind === 'node' && hovered.id === data.id,
        faded: focus ? !focus.nodeIds.has(data.id) : false,
        onPath: pathNodeIds.has(data.id),
      },
      badges: badgesOf(data),
      showConnectedCount: opts.showNbConnectedElements,
      typeLabel: typeLabel(data),
    });
    // Link labels are placed clear of the nodes at every zoom: the emphasised ones are drawn at overview zoom too.
    frameNodeBoxes.current.push(...covered);
  };

  /**
   * Draws node when in selected area.
   *
   * @param data Data of the node.
   * @param color The color to use.
   * @param ctx Context of the canvas.
   * @param globalScale Zoom level, the label is hit only where it is drawn.
   */
  const nodePointerAreaPaint = (
    data: GraphNode,
    color: string,
    ctx: CanvasRenderingContext2D,
    globalScale = DEFAULT_SCALE,
  ) => {
    paintGraphNodeHitArea(ctx, data, color, detailOf(globalScale).labels);
  };

  /** The colour of the relationship itself, whatever is selected or searched: the image export draws it. */
  const linkBaseColor = (link: GraphLink) => {
    if (link.isNestedInferred || link.inferred) return colors.inferred;
    if (link.disabled) return colors.disabled;
    return palette.link;
  };

  /**
   * Determines color of the link.
   *
   * @param link The link to chose color for.
   * @returns The color for the link.
   */
  const linkColorPaint = (link: GraphLink) => {
    const selected = selectedLinkIds.has(link.id);

    if (!selected && search) return colors.disabled;
    if (selected) return colors.selected;
    return linkBaseColor(link);
  };

  const bentCurvatures = useMemo(
    () => (bends ? new Map([...bends].map(([key, curvature]) => [key, { curvature, rotation: 0 }])) : null),
    [bends],
  );
  const curvatureOf = (link: GraphLink) => {
    const key = keyOf(link);
    return bentCurvatures?.get(key) ?? curvatures.get(key) ?? STRAIGHT_LINK;
  };
  const linkCurvature = (link: GraphLink) => curvatureOf(link).curvature;

  /** Labels collected while the links are drawn, painted over the nodes at the end of the frame. */
  const frameLabels = useRef<LinkLabel[]>([]);
  /** The options of every link of every frame, updated in place: the link painter reads them and keeps none. */
  const linkPaintOptions = useRef<LinkPaintOptions>({
    palette,
    globalScale: DEFAULT_SCALE,
    detail: levelOfDetail(DEFAULT_SCALE, 0),
    color: '',
    curvature: 0,
    rotation: 0,
    confidence: null,
    visual: { selected: false, hovered: false, faded: false, onPath: false },
  });
  /** What the nodes of the frame cover, which the link labels keep clear of. */
  const frameNodeBoxes = useRef<Box[]>([]);

  /**
   * Draws a link: curve, arrowhead and dash; its label is drawn at the end of the frame.
   *
   * @param link Link object from the lib of graphs.
   * @param ctx Context of the canvas.
   * @param globalScale Zoom level handed by the library.
   */
  const linkPaint = (link: GraphLink, ctx: CanvasRenderingContext2D, globalScale = DEFAULT_SCALE) => {
    const { curvature, rotation } = curvatureOf(link);
    const selected = selectedLinkIds.has(link.id);
    const key = keyOf(link);
    const options = linkPaintOptions.current;
    options.palette = palette;
    options.globalScale = globalScale;
    options.detail = detailOf(globalScale);
    options.color = link.disabled || (search && !selected) ? palette.textSecondary : linkColorPaint(link);
    options.curvature = curvature;
    options.rotation = rotation;
    options.confidence = link.confidence;
    options.visual.selected = selected;
    options.visual.hovered = isHoveredLink(hovered, endsOf(link));
    options.visual.faded = focus ? !focus.linkKeys.has(key) : false;
    options.visual.onPath = pathLinkKeys.has(key);
    const label = paintGraphLink(ctx, link, options);
    if (label) frameLabels.current.push(label);
  };

  /** To call before a frame: forgets the labels of the previous one, reusing the same buffers. */
  const framePrePaint = () => {
    frameLabels.current.length = 0;
    frameNodeBoxes.current.length = 0;
  };

  /** To call after a frame: draws the link labels that do not overlap. */
  const framePostPaint = (ctx: CanvasRenderingContext2D, globalScale: number) => {
    paintLinkLabels(ctx, frameLabels.current, { palette, globalScale, obstacles: frameNodeBoxes.current });
    frameLabels.current.length = 0;
    frameNodeBoxes.current.length = 0;
  };

  /**
   * Draws link between two nodes.
   * Kept for the callers drawing the default straight links: the label alone, at mid-link.
   *
   * @param link Link object from the lib of graphs.
   * @param ctx Context of the canvas.
   */
  const linkLabelPaint = (
    link: GraphLink,
    ctx: CanvasRenderingContext2D,
    globalScale = DEFAULT_SCALE,
  ) => {
    const start = link.source;
    const end = link.target;
    if (
      link.disabled
      || typeof start !== 'object'
      || typeof end !== 'object'
      || !Number.isFinite(start.x)
      || !Number.isFinite(end.x)
      || !link.label
    ) {
      return;
    }
    const middle = { x: start.x + (end.x - start.x) / 2, y: start.y + (end.y - start.y) / 2 };
    let angle = Math.atan2(end.y - start.y, end.x - start.x);
    if (angle > Math.PI / 2) angle -= Math.PI;
    if (angle < -Math.PI / 2) angle += Math.PI;
    paintLinkLabels(ctx, [{ text: link.label, x: middle.x, y: middle.y, angle, priority: 0, emphasised: false }], { palette, globalScale });
  };

  /** The sphere of a node in 3D: the selection accent when selected, as in 2D. */
  const nodeThreeColor = (node: GraphNode) => {
    if (selectedNodeIds.has(node.id)) return colors.selected;
    return node.disabled ? palette.disabled : node.color;
  };

  /** The label of a node in 3D, in the selection accent when selected. */
  const nodeThreeLabelColor = (node: GraphNode) => {
    if (selectedNodeIds.has(node.id)) return colors.selected;
    return node.disabled ? palette.disabled : palette.textSecondary;
  };

  /**
   * Draws a node for 3D mode.
   *
   * @param node Node to draw.
   */
  const nodeThreePaint = (node: GraphNode) => {
    const sprite = new SpriteText(node.label);
    sprite.color = nodeThreeLabelColor(node);
    sprite.textHeight = 1.5;
    return sprite;
  };

  /**
   * Draws a link for 3D mode.
   *
   * @param link Link to draw.
   */
  const linkThreePaint = (link: GraphLink) => {
    const sprite = new SpriteText(link.label);
    sprite.color = palette.textSecondary;
    sprite.textHeight = 1.5;
    return sprite;
  };

  /**
   * Set the position of link labels (at the middle of the link).
   *
   * @param sprite Sprite of the label.
   * @param coords Coordinates of the link.
   */
  const linkThreeLabelPosition: ForceGraphProps['linkPositionUpdate'] = (sprite, coords) => {
    const { start, end } = coords;
    Object.assign(sprite.position, {
      x: start.x + (end.x - start.x) / 2,
      y: start.y + (end.y - start.y) / 2,
      z: start.z + (end.z - start.z) / 2,
    });
  };

  return {
    palette,
    focus,
    nodePaint,
    nodePointerAreaPaint,
    linkLabelPaint,
    linkColorPaint,
    linkBaseColor,
    linkPaint,
    linkCurvature,
    curvatureOf,
    framePrePaint,
    framePostPaint,
    nodeThreeColor,
    nodeThreeLabelColor,
    nodeThreePaint,
    linkThreePaint,
    linkThreeLabelPosition,
  };
};

export default useGraphPainter;
