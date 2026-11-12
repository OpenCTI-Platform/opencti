import { createElement, type ComponentType } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import type { SvgIconProps } from '@mui/material/SvgIcon';
import ItemIcon from '../../ItemIcon';

/** Any MUI or mdi icon component: what badges and quick actions are drawn with. */
export type GraphCanvasIcon = ComponentType<SvgIconProps>;

type GlyphShape = { kind: 'path'; d: string } | { kind: 'circle'; cx: number; cy: number; r: number };

/**
 * An icon as canvas primitives on its own 24x24 box. The icons are the React components the rest
 * of the interface renders, read once as SVG markup, so the graph draws the very same glyph as
 * the lists, chips and menus.
 */
export interface CanvasGlyph {
  shapes: GlyphShape[];
}

const ICON_BOX = 24;
const EMPTY_GLYPH: CanvasGlyph = { shapes: [] };

const attribute = (element: string, name: string) => {
  const match = new RegExp(`\\s${name}="([^"]*)"`).exec(element);
  return match ? match[1] : null;
};

export const glyphFromMarkup = (markup: string): CanvasGlyph => {
  const shapes: GlyphShape[] = [];
  const elements = markup.match(/<(path|circle)\b[^>]*>/g) ?? [];
  elements.forEach((element) => {
    if (element.startsWith('<path')) {
      const d = attribute(element, 'd');
      if (d) shapes.push({ kind: 'path', d });
    } else {
      const cx = Number(attribute(element, 'cx'));
      const cy = Number(attribute(element, 'cy'));
      const r = Number(attribute(element, 'r'));
      if ([cx, cy, r].every(Number.isFinite) && r > 0) shapes.push({ kind: 'circle', cx, cy, r });
    }
  });
  return { shapes };
};

const renderGlyph = (element: Parameters<typeof renderToStaticMarkup>[0]): CanvasGlyph => {
  try {
    return glyphFromMarkup(renderToStaticMarkup(element));
  } catch {
    return EMPTY_GLYPH;
  }
};

const entityGlyphs = new Map<string, CanvasGlyph>();

/** The icon of an entity type, as drawn everywhere else in the interface (`ItemIcon`). */
export const entityGlyph = (entityType: string): CanvasGlyph => {
  let glyph = entityGlyphs.get(entityType);
  if (!glyph) {
    glyph = renderGlyph(createElement(ItemIcon, { type: entityType }));
    entityGlyphs.set(entityType, glyph);
  }
  return glyph;
};

const iconGlyphs = new WeakMap<GraphCanvasIcon, CanvasGlyph>();

export const iconGlyph = (icon: GraphCanvasIcon): CanvasGlyph => {
  let glyph = iconGlyphs.get(icon);
  if (!glyph) {
    glyph = renderGlyph(createElement(icon));
    iconGlyphs.set(icon, glyph);
  }
  return glyph;
};

const paths = new Map<string, Path2D>();
const pathOf = (d: string): Path2D | null => {
  if (typeof Path2D === 'undefined') return null;
  let path = paths.get(d);
  if (!path) {
    path = new Path2D(d);
    paths.set(d, path);
  }
  return path;
};

/**
 * Fills a glyph centred on (x, y) at `size` graph units. The context is saved and restored, so
 * the caller's transform and styles survive. Returns `false` when the glyph has nothing to draw.
 */
export const paintGlyph = (
  ctx: CanvasRenderingContext2D,
  glyph: CanvasGlyph,
  x: number,
  y: number,
  size: number,
  color: string,
): boolean => {
  if (glyph.shapes.length === 0) return false;
  const scale = size / ICON_BOX;
  ctx.save();
  ctx.translate(x - size / 2, y - size / 2);
  ctx.scale(scale, scale);
  ctx.fillStyle = color;
  glyph.shapes.forEach((shape) => {
    if (shape.kind === 'path') {
      const path = pathOf(shape.d);
      if (path) ctx.fill(path);
    } else {
      ctx.beginPath();
      ctx.arc(shape.cx, shape.cy, shape.r, 0, 2 * Math.PI);
      ctx.fill();
    }
  });
  ctx.restore();
  return true;
};
