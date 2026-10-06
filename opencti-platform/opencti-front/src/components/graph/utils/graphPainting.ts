import type { GraphLink, GraphNode } from '../graph.types';
import { dataColorOutline, type GraphPalette } from './graphPalette';
import { drawnBadges, type GraphBadge } from '../badges/graphBadgeRegistry';
import { entityGlyph, iconGlyph, paintGlyph } from './graphIcons';
import {
  type Box,
  createBoxIndex,
  createPathBuffer,
  fitText,
  linkPathInto,
  type LinkPath,
  type PathBuffer,
  type Point,
  pointAt,
  tangentAt,
  tangentInto,
  trimToNodesInto,
} from './graphGeometry';

/*
 * Sizes are graph units: the view is fitted to the drawing, so they only fix proportions. Sizes
 * that must stay readable whatever the zoom are given in screen pixels and divided by the scale.
 */
export const NODE_RADIUS = 6.5;
/** A relationship drawn as a node (it is the end of another relationship) is smaller than an entity. */
export const RELATIONSHIP_NODE_RADIUS = 4.5;
const RING_WIDTH = 1.1;
const ICON_SIZE_RATIO = 1.15;
const HALO_GAP = 1.8;
const HALO_WIDTH = 1.3;
const LABEL_GAP = 2.4;
const LABEL_SIZE = 3.6;
const SUBLABEL_SIZE = 2.7;
const LABEL_MAX_WIDTH = 48;
/** Emphasised labels (selected, hovered, on a path) never read smaller than this on screen. */
const EMPHASIS_LABEL_PX = 12;
/** And no label grows past this on screen when zooming in. */
const MAX_LABEL_PX = 18;
const PILL_PADDING = 1.2;
const BADGE_SIZE = 3.4;
const BADGE_MIN_PX = 10;
const BADGE_GAP = 0.7;
const COUNTER_RADIUS = 2.5;
const LINK_WIDTH = 0.55;
const LINK_MIN_PX = 1;
const LINK_GAP = 1.2;
const ARROW_LENGTH = 3.4;
const ARROW_HALF_WIDTH = 1.45;
const LINK_LABEL_SIZE = 2.6;
const LINK_LABEL_MAX_PX = 15;
const INFERRED_DASH = [2.4, 1.6];
const LOW_CONFIDENCE_DASH = [0.7, 1.5];
/** Below this confidence a relationship is drawn dotted: it is asserted with little certainty. */
export const LOW_CONFIDENCE_THRESHOLD = 50;
const DEFAULT_FONT = '"IBM Plex Sans", sans-serif';

export interface LevelOfDetail {
  icons: boolean;
  labels: boolean;
  secondaryLabels: boolean;
  badges: boolean;
  arrows: boolean;
  linkLabels: boolean;
}

/**
 * What is worth drawing at a zoom level: detail appears as it becomes readable, and a crowded
 * graph keeps its overview clean until the reader zooms in.
 */
export const levelOfDetail = (globalScale: number, nodeCount: number): LevelOfDetail => {
  const crowded = nodeCount > 500;
  const radiusPx = NODE_RADIUS * globalScale;
  return {
    icons: radiusPx >= 3.5,
    labels: LABEL_SIZE * globalScale >= (crowded ? 9 : 6.5),
    secondaryLabels: SUBLABEL_SIZE * globalScale >= 8.5,
    badges: radiusPx >= (crowded ? 10 : 7),
    arrows: ARROW_LENGTH * globalScale >= 3,
    linkLabels: LINK_LABEL_SIZE * globalScale >= (crowded ? 9 : 7),
  };
};

export const nodeRadius = (node: Pick<GraphNode, 'relationship_type'>) => (node.relationship_type ? RELATIONSHIP_NODE_RADIUS : NODE_RADIUS);

const font = (weight: number, size: number, family = DEFAULT_FONT) => `${weight} ${size}px ${family}`;

export interface NodeVisual {
  selected: boolean;
  /** The entity shown in the details panel. */
  preview: boolean;
  hovered: boolean;
  /** Outside the focus (selection, hover or path), drawn faded. */
  faded: boolean;
  onPath: boolean;
}

export interface NodePaintOptions {
  palette: GraphPalette;
  globalScale: number;
  detail: LevelOfDetail;
  visual: NodeVisual;
  badges?: GraphBadge[];
  /** Investigations show how many relationships are not drawn yet. */
  showConnectedCount?: boolean;
  /** Translated entity type, the second line of the label at close zoom. */
  typeLabel?: string;
}

const connectedCountLabel = (count: number | undefined): string | null => {
  if (count === undefined) return '?';
  if (count <= 0) return null;
  return count > 99 ? '99+' : `${count}+`;
};

const paintHalo = (ctx: CanvasRenderingContext2D, node: GraphNode, radius: number, color: string, alpha: number, width = HALO_WIDTH) => {
  const opacity = ctx.globalAlpha;
  ctx.beginPath();
  ctx.arc(node.x, node.y, radius + HALO_GAP + width / 2, 0, 2 * Math.PI);
  ctx.lineWidth = width;
  ctx.strokeStyle = color;
  ctx.globalAlpha = opacity * alpha;
  ctx.stroke();
  ctx.globalAlpha = opacity;
};

/**
 * Draws the badge row above a node, at most `MAX_DRAWN_BADGES` of them followed by a "+N" marker
 * for the others; returns the box it covers.
 */
const paintBadges = (ctx: CanvasRenderingContext2D, node: GraphNode, radius: number, badges: GraphBadge[], options: NodePaintOptions): Box => {
  const { palette, globalScale } = options;
  const { drawn, more } = drawnBadges(badges);
  const size = Math.max(BADGE_SIZE, BADGE_MIN_PX / globalScale);
  const gap = BADGE_GAP * (size / BADGE_SIZE);
  ctx.font = font(600, size * 0.62);
  const moreText = more > 0 ? `+${more}` : null;
  const moreWidth = moreText ? ctx.measureText(moreText).width + size * 0.7 : 0;
  const widths = drawn.map((badge) => (badge.value !== undefined && badge.value !== ''
    ? size + ctx.measureText(String(badge.value)).width + size * 0.35
    : size));
  const pills = widths.length + (moreText ? 1 : 0);
  const total = widths.reduce((sum, width) => sum + width, 0) + moreWidth + gap * (pills - 1);
  const centreY = node.y - radius - HALO_GAP - size / 2 - gap;
  let left = node.x - total / 2;
  drawn.forEach((badge, index) => {
    const width = widths[index];
    const color = badge.color || palette.tones[badge.tone];
    const outline = badge.color ? dataColorOutline(badge.color, palette) : null;
    ctx.beginPath();
    ctx.roundRect(left, centreY - size / 2, width, size, size / 2);
    ctx.fillStyle = palette.surface;
    ctx.fill();
    ctx.lineWidth = size * 0.12;
    ctx.strokeStyle = outline ?? color;
    ctx.stroke();
    const glyphCentre = left + size / 2;
    const painted = badge.icon ? paintGlyph(ctx, iconGlyph(badge.icon), glyphCentre, centreY, size * 0.68, color) : false;
    if (!painted) {
      ctx.beginPath();
      ctx.arc(glyphCentre, centreY, size * 0.26, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      if (outline) {
        ctx.lineWidth = size * 0.08;
        ctx.strokeStyle = outline;
        ctx.stroke();
      }
    }
    if (badge.value !== undefined && badge.value !== '') {
      ctx.fillStyle = palette.text;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(String(badge.value), left + size * 0.95, centreY + size * 0.04);
    }
    left += width + gap;
  });
  if (moreText) {
    ctx.beginPath();
    ctx.roundRect(left, centreY - size / 2, moreWidth, size, size / 2);
    ctx.fillStyle = palette.surface;
    ctx.fill();
    ctx.lineWidth = size * 0.12;
    ctx.strokeStyle = palette.textSecondary;
    ctx.stroke();
    ctx.fillStyle = palette.text;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(moreText, left + moreWidth / 2, centreY + size * 0.04);
  }
  return { x: node.x, y: centreY, halfWidth: total / 2, halfHeight: size / 2 };
};

/** Draws the name (and the type close up) under a node; returns the box the text covers. */
const paintLabels = (ctx: CanvasRenderingContext2D, node: GraphNode, radius: number, options: NodePaintOptions, emphasised: boolean): Box => {
  const { palette, globalScale, visual, detail, typeLabel } = options;
  const base = emphasised ? Math.max(LABEL_SIZE, EMPHASIS_LABEL_PX / globalScale) : LABEL_SIZE;
  const size = Math.min(base, MAX_LABEL_PX / globalScale);
  const top = node.y + radius + LABEL_GAP + (visual.selected || visual.preview ? HALO_WIDTH : 0);
  ctx.font = font(visual.selected || visual.preview ? 600 : 500, size);
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  const text = fitText((value) => ctx.measureText(value).width, node.label ?? '', LABEL_MAX_WIDTH * (size / LABEL_SIZE));
  if (visual.selected || visual.preview) {
    const width = ctx.measureText(text).width + PILL_PADDING * 2 * (size / LABEL_SIZE);
    ctx.beginPath();
    ctx.roundRect(node.x - width / 2, top - size * 0.2, width, size * 1.4, size * 0.35);
    ctx.fillStyle = palette.accent;
    ctx.fill();
    ctx.fillStyle = palette.background;
  } else {
    ctx.fillStyle = node.disabled ? palette.textSecondary : palette.text;
  }
  ctx.fillText(text, node.x, top);
  let halfWidth = ctx.measureText(text).width / 2 + PILL_PADDING;
  let height = size * 1.4;
  if (typeLabel && detail.secondaryLabels && !node.disabled) {
    const subSize = Math.min(SUBLABEL_SIZE, (MAX_LABEL_PX * 0.8) / globalScale);
    ctx.font = font(400, subSize);
    ctx.fillStyle = palette.textSecondary;
    const subText = fitText((value) => ctx.measureText(value).width, typeLabel, LABEL_MAX_WIDTH * (subSize / LABEL_SIZE));
    ctx.fillText(subText, node.x, top + size * 1.3);
    halfWidth = Math.max(halfWidth, ctx.measureText(subText).width / 2 + PILL_PADDING);
    height = size * 1.3 + subSize * 1.3;
  }
  return { x: node.x, y: top + height / 2 - size * 0.2, halfWidth, halfHeight: height / 2 };
};

/**
 * Draws one node: a disc tinted with the entity colour, its ring and icon, the selection halo,
 * the badges above and the label below, each according to the level of detail. Returns the boxes
 * the disc and the label cover, which link labels keep clear of.
 */
export const paintGraphNode = (ctx: CanvasRenderingContext2D, node: GraphNode, options: NodePaintOptions): Box[] => {
  const { palette, detail, visual, badges = [], showConnectedCount = false } = options;
  if (!Number.isFinite(node.x) || !Number.isFinite(node.y)) return [];
  const radius = nodeRadius(node);
  const covered: Box[] = [{ x: node.x, y: node.y, halfWidth: radius + HALO_GAP, halfHeight: radius + HALO_GAP }];
  const color = node.disabled ? palette.textSecondary : (node.color || palette.textSecondary);
  ctx.save();
  let alpha = 1;
  if (node.disabled) alpha = palette.fadeAlpha * 0.7;
  else if (visual.faded) alpha = palette.fadeAlpha;
  ctx.globalAlpha = alpha;

  if (visual.selected || visual.preview || visual.onPath) {
    paintHalo(ctx, node, radius, palette.accent, visual.preview ? 1 : 0.8);
  } else if (visual.hovered) {
    paintHalo(ctx, node, radius, color, 0.55);
  }

  // Opaque first, so a link behind never shows through the tint.
  ctx.beginPath();
  ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI);
  ctx.fillStyle = palette.surface;
  ctx.fill();
  ctx.globalAlpha = alpha * palette.tintAlpha;
  ctx.fillStyle = color;
  ctx.fill();
  ctx.globalAlpha = alpha;
  ctx.lineWidth = RING_WIDTH;
  ctx.strokeStyle = node.isNestedInferred ? palette.inferred : color;
  // A dashed outline marks what is not knowledge the reader fully sees: inferred, or restricted to them.
  if (node.isNestedInferred || node.isRestricted) ctx.setLineDash([1.6, 1.1]);
  ctx.stroke();
  ctx.setLineDash([]);

  if (detail.icons) {
    const glyph = entityGlyph(node.relationship_type ? 'relationship' : node.entity_type);
    const size = radius * ICON_SIZE_RATIO;
    const painted = paintGlyph(ctx, glyph, node.x, node.y, size, color);
    if (!painted && node.img?.complete && node.img.naturalWidth > 0) {
      ctx.drawImage(node.img, node.x - size / 2, node.y - size / 2, size, size);
    }
  }

  const counter = showConnectedCount ? connectedCountLabel(node.numberOfConnectedElement) : null;
  if (counter) {
    const cx = node.x + radius * 0.78;
    const cy = node.y - radius * 0.78;
    ctx.beginPath();
    ctx.arc(cx, cy, COUNTER_RADIUS, 0, 2 * Math.PI);
    ctx.fillStyle = palette.background;
    ctx.fill();
    ctx.lineWidth = 0.4;
    ctx.strokeStyle = color;
    ctx.stroke();
    ctx.fillStyle = palette.text;
    ctx.font = font(600, counter.length > 2 ? 1.5 : 1.8);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(counter, cx, cy + 0.1);
  }

  if (badges.length > 0 && detail.badges && !node.disabled) {
    covered.push(paintBadges(ctx, node, radius, badges, options));
  }

  const emphasised = visual.selected || visual.preview || visual.hovered || visual.onPath;
  if (detail.labels || emphasised) {
    covered.push(paintLabels(ctx, node, radius, options, emphasised));
  }
  ctx.restore();
  return covered;
};

/** The area a pointer hits for a node: its disc with a little margin, and its label when drawn. */
export const paintGraphNodeHitArea = (ctx: CanvasRenderingContext2D, node: GraphNode, color: string, showLabel: boolean) => {
  const radius = nodeRadius(node);
  ctx.beginPath();
  ctx.fillStyle = color;
  ctx.arc(node.x, node.y, radius + 1.5, 0, 2 * Math.PI);
  ctx.fill();
  if (showLabel) {
    ctx.fillRect(node.x - LABEL_MAX_WIDTH / 4, node.y + radius, LABEL_MAX_WIDTH / 2, LABEL_GAP + LABEL_SIZE * 1.4);
  }
};

export interface LinkVisual {
  selected: boolean;
  hovered: boolean;
  faded: boolean;
  onPath: boolean;
}

export interface LinkPaintOptions {
  palette: GraphPalette;
  globalScale: number;
  detail: LevelOfDetail;
  visual: LinkVisual;
  color: string;
  curvature: number;
  rotation: number;
  /** Confidence of the relationship, when known. */
  confidence?: number | null;
}

export interface LinkLabel {
  text: string;
  x: number;
  y: number;
  angle: number;
  /** Selected and focused labels are kept first when labels overlap. */
  priority: number;
  emphasised: boolean;
  /** Other places along the link, tried in order when the middle is taken. */
  alternatives?: { x: number; y: number; angle: number }[];
}

/** Where along a link its label may go: the middle first, then a little towards each end. */
const LABEL_SPOTS = [0.5, 0.33, 0.67];

const readableAngle = (tangent: { x: number; y: number }) => {
  let angle = Math.atan2(tangent.y, tangent.x);
  if (angle > Math.PI / 2) angle -= Math.PI;
  if (angle < -Math.PI / 2) angle += Math.PI;
  return angle;
};

const endOf = (end: GraphLink['source']) => (typeof end === 'object' && end !== null ? end : null);

export const linkDash = (link: Pick<GraphLink, 'inferred' | 'isNestedInferred'>, confidence?: number | null): number[] => {
  if (link.inferred || link.isNestedInferred) return INFERRED_DASH;
  if (typeof confidence === 'number' && confidence < LOW_CONFIDENCE_THRESHOLD) return LOW_CONFIDENCE_DASH;
  return [];
};

const strokePath = (ctx: CanvasRenderingContext2D, path: LinkPath | PathBuffer) => {
  ctx.beginPath();
  ctx.moveTo(path.start.x, path.start.y);
  if (path.kind === 'line') ctx.lineTo(path.end.x, path.end.y);
  else if (path.kind === 'quadratic') ctx.quadraticCurveTo(path.control.x, path.control.y, path.end.x, path.end.y);
  else ctx.bezierCurveTo(path.c1.x, path.c1.y, path.c2.x, path.c2.y, path.end.x, path.end.y);
  ctx.stroke();
};

const paintArrowHead = (ctx: CanvasRenderingContext2D, tip: { x: number; y: number }, direction: { x: number; y: number }, scale: number) => {
  const length = ARROW_LENGTH * scale;
  const half = ARROW_HALF_WIDTH * scale;
  const tailX = tip.x - direction.x * length;
  const tailY = tip.y - direction.y * length;
  ctx.beginPath();
  ctx.moveTo(tip.x, tip.y);
  ctx.lineTo(tailX - direction.y * half, tailY + direction.x * half);
  ctx.lineTo(tailX + direction.y * half, tailY - direction.x * half);
  ctx.closePath();
  ctx.fill();
};

/**
 * Draws one link: the curve between the two rings, its arrowhead, its dash when uncertain.
 * Returns the label to draw once every node is painted, or `null`.
 */
// The geometry of the link being painted, filled in place for every link of every frame
const linkPathBuffer = createPathBuffer();
const trimmedPathBuffer = createPathBuffer();
const arrowDirection: Point = { x: 0, y: 0 };

export const paintGraphLink = (ctx: CanvasRenderingContext2D, link: GraphLink, options: LinkPaintOptions): LinkLabel | null => {
  const { palette, globalScale, detail, visual, color, curvature, rotation, confidence } = options;
  const source = endOf(link.source);
  const target = endOf(link.target);
  if (!source || !target || !Number.isFinite(source.x) || !Number.isFinite(target.x)) return null;
  const path = linkPathInto(linkPathBuffer, source, target, curvature, rotation);
  const trimmed = trimmedPathBuffer;
  if (!trimToNodesInto(trimmed, path, nodeRadius(source) + LINK_GAP, nodeRadius(target) + LINK_GAP)) return null;

  const emphasis = visual.onPath || visual.selected || visual.hovered;
  let alpha = 0.72;
  if (link.disabled) alpha = palette.fadeAlpha * 0.6;
  else if (visual.faded) alpha = palette.fadeAlpha;
  else if (emphasis) alpha = 1;
  let widthFactor = 1;
  if (visual.onPath) widthFactor = 2.6;
  else if (visual.selected) widthFactor = 2.2;
  else if (visual.hovered) widthFactor = 1.6;

  ctx.save();
  ctx.globalAlpha = alpha;
  ctx.strokeStyle = visual.onPath ? palette.accent : color;
  ctx.fillStyle = ctx.strokeStyle;
  ctx.lineWidth = Math.max(LINK_WIDTH, LINK_MIN_PX / globalScale) * widthFactor;
  ctx.lineCap = 'round';
  ctx.setLineDash(linkDash(link, confidence));
  strokePath(ctx, trimmed);
  ctx.setLineDash([]);
  const isConnector = !link.label;
  if ((detail.arrows || emphasis) && !(isConnector && link.target_id === link.id)) {
    paintArrowHead(ctx, trimmed.end, tangentInto(arrowDirection, trimmed, 1), emphasis ? Math.min(1.5, widthFactor * 0.75) : 1);
  }
  ctx.restore();

  if (!link.label || link.disabled || !(detail.linkLabels || emphasis)) return null;
  const [middle, ...alternatives] = LABEL_SPOTS.map((t) => ({ ...pointAt(trimmed, t), angle: readableAngle(tangentAt(trimmed, t)) }));
  let priority = 0;
  if (visual.selected) priority = 3;
  else if (visual.onPath) priority = 2;
  else if (visual.hovered) priority = 1;
  return { text: link.label, ...middle, priority, emphasised: emphasis && !visual.faded, alternatives };
};

const rotatedBox = (spot: { x: number; y: number; angle: number }, width: number, height: number): Box => {
  const cos = Math.abs(Math.cos(spot.angle));
  const sin = Math.abs(Math.sin(spot.angle));
  return {
    x: spot.x,
    y: spot.y,
    halfWidth: (width * cos + height * sin) / 2,
    halfHeight: (width * sin + height * cos) / 2,
  };
};

/**
 * Draws the link labels over everything else, most important first. A label goes to the middle
 * of its link, or a little towards an end when the middle would cover a node (`obstacles`, what
 * the nodes drew) or a label already placed; a label with no free place is left out, since a
 * half-hidden label names nothing, unless it is emphasised (selected, hovered, on a path).
 */
export const paintLinkLabels = (
  ctx: CanvasRenderingContext2D,
  labels: readonly LinkLabel[],
  options: { palette: GraphPalette; globalScale: number; obstacles?: readonly Box[] },
) => {
  if (labels.length === 0) return;
  const { palette, globalScale, obstacles = [] } = options;
  const size = Math.min(LINK_LABEL_SIZE, LINK_LABEL_MAX_PX / globalScale);
  ctx.save();
  ctx.font = font(500, size);
  const taken = createBoxIndex(Math.max(size * 8, 4));
  obstacles.forEach(taken.add);
  const placed: { label: LinkLabel; spot: { x: number; y: number; angle: number } }[] = [];
  [...labels].sort((a, b) => b.priority - a.priority).forEach((label) => {
    const width = ctx.measureText(label.text).width + size;
    const spots = [label, ...(label.alternatives ?? [])];
    const free = spots.map((spot) => ({ spot, box: rotatedBox(spot, width, size * 1.5) })).find(({ box }) => !taken.overlaps(box));
    const chosen = free ?? (label.priority > 0 ? { spot: label, box: rotatedBox(label, width, size * 1.5) } : null);
    if (!chosen) return;
    taken.add(chosen.box);
    placed.push({ label, spot: chosen.spot });
  });
  placed.forEach(({ label, spot }) => {
    ctx.save();
    ctx.translate(spot.x, spot.y);
    ctx.rotate(spot.angle);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.lineJoin = 'round';
    ctx.lineWidth = size * 0.5;
    ctx.strokeStyle = palette.background;
    ctx.strokeText(label.text, 0, 0);
    ctx.fillStyle = label.emphasised ? palette.text : palette.textSecondary;
    ctx.fillText(label.text, 0, 0);
    ctx.restore();
  });
  ctx.restore();
};
