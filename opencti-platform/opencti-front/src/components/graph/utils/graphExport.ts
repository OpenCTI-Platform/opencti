import type { GraphLink, GraphNode } from '../graph.types';
import type { GraphPalette } from './graphPalette';
import type { GraphBadge } from '../badges/graphBadgeRegistry';
import { boundsOf, computeLinkCurvatures, type LinkEnds, linkEndsKey, linkPath } from './graphGeometry';
import { type LinkLabel, levelOfDetail, linkDash, paintGraphLink, paintGraphNode, paintLinkLabels } from './graphPainting';

export interface GraphExportLegendEntry {
  label: string;
  color: string;
  count: number;
}

export interface GraphExportInput {
  nodes: readonly GraphNode[];
  links: readonly GraphLink[];
  palette: GraphPalette;
  title?: string;
  subtitle?: string;
  typeLabel: (node: GraphNode) => string;
  badgesOf: (node: GraphNode) => GraphBadge[];
  linkColor: (link: GraphLink) => string;
  legend: {
    title: string;
    entities: GraphExportLegendEntry[];
    lineStyles: { label: string; kind: 'asserted' | 'inferred' | 'lowConfidence' }[];
  };
  showConnectedCount?: boolean;
  /** Curvature of each link as drawn on screen; the parallel-link fan-out when not given. */
  curvatureOf?: (link: GraphLink) => { curvature: number; rotation: number };
  /** Image pixels per graph unit; lowered when the image would exceed the maximum size. */
  pixelsPerUnit?: number;
}

const MAX_SIDE = 8000;
const DEFAULT_PIXELS_PER_UNIT = 5;
/** Graph units around the drawing, for the labels and badges the node positions do not cover. */
const DRAWING_MARGIN = 40;
/**
 * Pixels the badges reach around a node at the least: they keep a minimum size in pixels, so once a
 * large graph is scaled down they cover more graph units than `DRAWING_MARGIN`.
 */
const DECORATION_MIN_PX = 48;
const LEGEND_WIDTH = 280;
const LEGEND_ROW = 26;
const HEADER_HEIGHT = 72;
const PADDING = 32;
const FONT = '"IBM Plex Sans", sans-serif';

const endpoint = (end: GraphLink['source']) => (typeof end === 'object' && end !== null ? end : null);

/**
 * Renders the whole graph, not only the visible area, into a canvas sized for print, with a title
 * and a legend of the entity types and line styles. Every element is drawn at full strength and
 * full detail, whatever the focus and zoom on screen. `null` when there is nothing to draw.
 */
export const renderGraphImage = (
  input: GraphExportInput,
  createCanvas: () => HTMLCanvasElement = () => document.createElement('canvas'),
): HTMLCanvasElement | null => {
  const { nodes, links, palette, legend } = input;
  const endsOf = (link: GraphLink): LinkEnds => ({
    id: link.id,
    sourceId: endpoint(link.source)?.id ?? link.source_id,
    targetId: endpoint(link.target)?.id ?? link.target_id,
  });
  const curvatures = computeLinkCurvatures(links.map(endsOf));
  const curvatureOf = (link: GraphLink) => input.curvatureOf?.(link) ?? curvatures.get(linkEndsKey(endsOf(link))) ?? { curvature: 0, rotation: 0 };
  const drawable = nodes.filter((n) => Number.isFinite(n.x) && Number.isFinite(n.y));
  // Curves and self-loops reach beyond the nodes: their control points bound them.
  const positions = new Map(drawable.map((n) => [n.id, { x: n.x as number, y: n.y as number }]));
  const controlPoints = links.flatMap((link) => {
    const start = positions.get(endpoint(link.source)?.id ?? link.source_id);
    const end = positions.get(endpoint(link.target)?.id ?? link.target_id);
    if (!start || !end) return [];
    const { curvature, rotation } = curvatureOf(link);
    const path = linkPath(start, end, curvature, rotation);
    if (path.kind === 'quadratic') return [path.control];
    if (path.kind === 'cubic') return [path.c1, path.c2];
    return [];
  });
  const bounds = boundsOf([...positions.values(), ...controlPoints]);
  if (!bounds) return null;
  const extentX = bounds.maxX - bounds.minX;
  const extentY = bounds.maxY - bounds.minY;
  const marginAt = (k: number) => Math.max(DRAWING_MARGIN, DECORATION_MIN_PX / k);
  const legendHeight = PADDING * 2 + LEGEND_ROW * (legend.entities.length + legend.lineStyles.length + 2);
  let scale = input.pixelsPerUnit ?? DEFAULT_PIXELS_PER_UNIT;
  const sizeAt = (k: number) => ({
    width: Math.ceil((extentX + marginAt(k) * 2) * k + LEGEND_WIDTH + PADDING * 2),
    height: Math.ceil(Math.max((extentY + marginAt(k) * 2) * k, legendHeight) + HEADER_HEIGHT + PADDING),
  });
  // The largest scale at which an extent and its margins fit in the pixels available: the margin is
  // `DRAWING_MARGIN` graph units, or `DECORATION_MIN_PX` pixels once the scale makes that larger.
  const fitScale = (available: number, extent: number) => {
    const withUnitMargin = available / (extent + DRAWING_MARGIN * 2);
    if (withUnitMargin >= DECORATION_MIN_PX / DRAWING_MARGIN) return withUnitMargin;
    return extent > 0 ? (available - DECORATION_MIN_PX * 2) / extent : Infinity;
  };
  let size = sizeAt(scale);
  if (size.width > MAX_SIDE || size.height > MAX_SIDE) {
    // One pixel of margin, which the rounding up of the sizes may take.
    scale = Math.min(
      scale,
      fitScale(MAX_SIDE - 1 - LEGEND_WIDTH - PADDING * 2, extentX),
      fitScale(MAX_SIDE - 1 - HEADER_HEIGHT - PADDING, extentY),
    );
    size = sizeAt(scale);
  }
  const margin = marginAt(scale);
  const canvas = createCanvas();
  canvas.width = size.width;
  canvas.height = size.height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  ctx.fillStyle = palette.background;
  ctx.fillRect(0, 0, size.width, size.height);

  // Header.
  ctx.textAlign = 'left';
  ctx.textBaseline = 'top';
  ctx.fillStyle = palette.text;
  ctx.font = `600 22px ${FONT}`;
  if (input.title) ctx.fillText(input.title, PADDING, PADDING * 0.6);
  if (input.subtitle) {
    ctx.font = `400 14px ${FONT}`;
    ctx.fillStyle = palette.textSecondary;
    ctx.fillText(input.subtitle, PADDING, PADDING * 0.6 + 30);
  }

  // Drawing.
  const detail = levelOfDetail(Math.max(scale, 4), 0);
  ctx.save();
  ctx.translate(PADDING - (bounds.minX - margin) * scale, HEADER_HEIGHT - (bounds.minY - margin) * scale);
  ctx.scale(scale, scale);
  const labels: LinkLabel[] = [];
  links.forEach((link) => {
    const { curvature, rotation } = curvatureOf(link);
    const label = paintGraphLink(ctx, link, {
      palette,
      globalScale: scale,
      detail,
      visual: { selected: false, hovered: false, faded: false, onPath: false },
      color: input.linkColor(link),
      curvature,
      rotation,
      confidence: link.confidence,
    });
    if (label) labels.push(label);
  });
  const covered = nodes.flatMap((node) => paintGraphNode(ctx, node, {
    palette,
    globalScale: scale,
    detail,
    visual: { selected: false, preview: false, hovered: false, faded: false, onPath: false },
    badges: input.badgesOf(node),
    showConnectedCount: input.showConnectedCount,
    typeLabel: input.typeLabel(node),
  }));
  paintLinkLabels(ctx, labels, { palette, globalScale: scale, obstacles: covered });
  ctx.restore();

  // Legend.
  const left = size.width - LEGEND_WIDTH - PADDING / 2;
  let top = HEADER_HEIGHT;
  ctx.fillStyle = palette.surface;
  ctx.beginPath();
  ctx.roundRect(left, top, LEGEND_WIDTH, legendHeight - PADDING, 8);
  ctx.fill();
  top += PADDING * 0.6;
  ctx.fillStyle = palette.text;
  ctx.font = `600 15px ${FONT}`;
  ctx.textBaseline = 'middle';
  ctx.fillText(legend.title, left + 16, top + LEGEND_ROW / 2);
  top += LEGEND_ROW;
  legend.entities.forEach((entry) => {
    const cy = top + LEGEND_ROW / 2;
    ctx.beginPath();
    ctx.arc(left + 24, cy, 7, 0, 2 * Math.PI);
    ctx.fillStyle = palette.surface;
    ctx.fill();
    ctx.globalAlpha = palette.tintAlpha;
    ctx.fillStyle = entry.color;
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.lineWidth = 2;
    ctx.strokeStyle = entry.color;
    ctx.stroke();
    ctx.font = `400 13px ${FONT}`;
    ctx.fillStyle = palette.text;
    ctx.textAlign = 'left';
    ctx.fillText(entry.label, left + 42, cy);
    ctx.textAlign = 'right';
    ctx.fillStyle = palette.textSecondary;
    ctx.fillText(String(entry.count), left + LEGEND_WIDTH - 16, cy);
    top += LEGEND_ROW;
  });
  top += LEGEND_ROW / 2;
  legend.lineStyles.forEach((style) => {
    const cy = top + LEGEND_ROW / 2;
    ctx.save();
    ctx.strokeStyle = style.kind === 'inferred' ? palette.inferred : palette.link;
    ctx.lineWidth = 2;
    const dash = linkDash(
      { inferred: style.kind === 'inferred', isNestedInferred: false },
      style.kind === 'lowConfidence' ? 0 : null,
    ).map((value) => value * 3);
    ctx.setLineDash(dash);
    ctx.beginPath();
    ctx.moveTo(left + 14, cy);
    ctx.lineTo(left + 34, cy);
    ctx.stroke();
    ctx.restore();
    ctx.font = `400 13px ${FONT}`;
    ctx.fillStyle = palette.text;
    ctx.textAlign = 'left';
    ctx.fillText(style.label, left + 42, cy);
    top += LEGEND_ROW;
  });
  return canvas;
};

/** Saves a canvas as a PNG file through a temporary link. */
export const downloadCanvasAsPng = (canvas: HTMLCanvasElement, fileName: string): Promise<void> => new Promise((resolve, reject) => {
  canvas.toBlob((blob) => {
    if (!blob) {
      reject(new Error('The graph image could not be encoded'));
      return;
    }
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName.endsWith('.png') ? fileName : `${fileName}.png`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    resolve();
  }, 'image/png');
});
