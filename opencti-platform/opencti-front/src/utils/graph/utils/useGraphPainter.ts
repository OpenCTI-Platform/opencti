import { useTheme } from '@mui/material/styles';
import SpriteText from 'three-spritetext';
import { ForceGraphProps } from 'react-force-graph-3d';
import type { Theme } from '../../../components/Theme';
import type { GraphLink, GraphNode } from '../graph.types';
import { useGraphContext } from './GraphContext';

interface PaintOptions {
  showNbConnectedElements?: boolean
}

const useGraphPainter = () => {
  const theme = useTheme<Theme>();
  const { selectedLinks, selectedNodes } = useGraphContext();

  const DEFAULT_COLOR = '#0fbcff'; // Normally never used (all colors are defined).
  const colors = {
    selected: theme.palette.secondary.main ?? DEFAULT_COLOR,
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    inferred: theme.palette.warning?.main ?? DEFAULT_COLOR,
    numbersBackground: theme.palette.background.default ?? DEFAULT_COLOR,
    numberText: theme.palette.text?.secondary ?? DEFAULT_COLOR,
    linkText: theme.palette.text?.primary ?? DEFAULT_COLOR,
    disabled: theme.palette.background.paper ?? DEFAULT_COLOR,
  };

  /**
   * Draws a node in canvas.
   *
   * @param ctx Context of the canvas.
   * @param data Data associated to the node.
   * @param opts Options to change drawing.
   */
  const nodePaint = (
    data: GraphNode,
    ctx: CanvasRenderingContext2D,
    opts: PaintOptions = {},
  ) => {
    const { label, img, x, y, numberOfConnectedElement, color, disabled, isNestedInferred } = data;
    const { showNbConnectedElements } = opts;
    const selected = !!selectedNodes.find((n) => n.id === data.id);

    ctx.beginPath();
    ctx.fillStyle = disabled ? colors.disabled : color;
    ctx.arc(x, y, 5, 0, 2 * Math.PI, false);
    ctx.fill();

    if (selected) {
      ctx.lineWidth = 0.8;
      ctx.strokeStyle = colors.selected;
      ctx.stroke();
    } else if (isNestedInferred) {
      ctx.lineWidth = 0.8;
      ctx.strokeStyle = colors.inferred;
      ctx.stroke();
    }

    const size = 8;
    ctx.drawImage(img, x - size / 2, y - size / 2, size, size);
    ctx.font = '4px IBM Plex Sans';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(label, x, y + 9);

    const validConnectedElements = numberOfConnectedElement === undefined || numberOfConnectedElement > 0;
    if (showNbConnectedElements && validConnectedElements) {
      ctx.beginPath();
      ctx.arc(x + 4, y - 3, 2, 0, 2 * Math.PI, false);
      ctx.lineWidth = 0.4;
      ctx.strokeStyle = color;
      ctx.stroke();
      ctx.fillStyle = colors.numbersBackground;
      ctx.fill();
      ctx.fillStyle = colors.numberText;
      let numberLabel = '?';
      if (numberOfConnectedElement !== undefined) {
        numberLabel = `${numberOfConnectedElement}`;
      }
      if (numberLabel !== '?') {
        numberLabel = (numberOfConnectedElement ?? 0) > 99 ? '99+' : `${numberLabel}+`;
      }
      ctx.font = '1.5px IBM Plex Sans';
      ctx.fillText(numberLabel, x + 4, y - 2.9);
    }
  };

  /**
   * Draws node when in selected area.
   *
   * @param data Data of the node.
   * @param color The color to use.
   * @param ctx Context of the canvas.
   */
  const nodePointerAreaPaint = (
    data: GraphNode,
    color: string,
    ctx: CanvasRenderingContext2D,
  ) => {
    const { name, x, y } = data;

    ctx.beginPath();
    ctx.fillStyle = color;
    ctx.arc(x, y, 5, 0, 2 * Math.PI, false);
    ctx.fill();
    ctx.font = '4px IBM Plex Sans';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(name, x, y + 10);
  };

  /**
   * Determines color of the link.
   *
   * @param link The link to chose color for.
   * @returns The color for the link.
   */
  const linkColorPaint = (link: GraphLink) => {
    const selected = !!selectedLinks.find((l) => l.id === link.id);

    if (selected) return colors.selected;
    if (link.isNestedInferred) return colors.inferred;
    if (link.disabled) return colors.disabled;
    return theme.palette.primary.main;
  };

  /**
   * Draws link between two nodes.
   *
   * @param link Link object from the lib of graphs.
   * @param ctx Context of the canvas.
   */
  const linkLabelPaint = (
    link: GraphLink,
    ctx: CanvasRenderingContext2D,
  ) => {
    const start = link.source;
    const end = link.target;
    if (
      link.disabled
      || typeof start !== 'object'
      || typeof end !== 'object'
      || start.x === undefined
      || end.x === undefined
      || start.y === undefined
      || end.y === undefined) {
      return;
    }

    const textPos = {
      x: start.x + (end.x - start.x) / 2,
      y: start.y + (end.y - start.y) / 2,
    };
    const relLink = {
      x: end.x - start.x,
      y: end.y - start.y,
    };

    let textAngle = Math.atan2(relLink.y, relLink.x);
    if (textAngle > Math.PI / 2) textAngle = -(Math.PI - textAngle);
    if (textAngle < -Math.PI / 2) textAngle = -(-Math.PI - textAngle);
    const fontSize = 3;
    ctx.font = `${fontSize}px IBM Plex Sans`;
    ctx.save();
    ctx.translate(textPos.x, textPos.y);
    ctx.rotate(textAngle);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = colors.linkText;
    ctx.fillText(link.label, 0, 0);
    ctx.restore();
  };

  /**
   * Draws a node for 3D mode.
   *
   * @param node Node to draw.
   */
  const nodeThreePaint = (node: GraphNode) => {
    const sprite = new SpriteText(node.label);
    sprite.color = colors.linkText;
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
    sprite.color = 'lightgrey';
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
    nodePaint,
    nodePointerAreaPaint,
    linkLabelPaint,
    linkColorPaint,
    nodeThreePaint,
    linkThreePaint,
    linkThreeLabelPosition,
  };
};

export default useGraphPainter;
