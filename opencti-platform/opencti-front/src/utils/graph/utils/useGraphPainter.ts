import { useTheme } from '@mui/material/styles';
import { LinkObject } from 'react-force-graph-2d';
import SpriteText from 'three-spritetext';
import type { Theme } from '../../../components/Theme';

interface PaintData {
  label: string
  name: string
  img: CanvasImageSource
  x: number
  y: number
  numberOfConnectedElement: number
}

interface PaintOptions {
  color: string
  selected?: boolean
  inferred?: boolean
  disabled?: boolean
  showNbConnectedElements?: boolean
}

const useGraphPainter = () => {
  const theme = useTheme<Theme>();
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
    data: PaintData,
    opts: PaintOptions,
    ctx: CanvasRenderingContext2D,
  ) => {
    const { label, img, x, y, numberOfConnectedElement } = data;
    const { disabled, inferred, selected, showNbConnectedElements, color } = opts;

    ctx.beginPath();
    ctx.fillStyle = disabled ? colors.disabled : color;
    ctx.arc(x, y, 5, 0, 2 * Math.PI, false);
    ctx.fill();

    if (selected) {
      ctx.lineWidth = 0.8;
      ctx.strokeStyle = colors.selected;
      ctx.stroke();
    } else if (inferred) {
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
        numberLabel = numberOfConnectedElement > 99 ? '99+' : `${numberLabel}+`;
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
    data: PaintData,
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
   * Draws link between two nodes.
   *
   * @param link Link object from the lib of graphs.
   * @param ctx Context of the canvas.
   */
  const linkPaint = (
    link: LinkObject,
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
  const nodeThreePaint = (node: PaintData) => {
    const sprite = new SpriteText(node.label);
    sprite.color = colors.linkText;
    sprite.textHeight = 1.5;
    return sprite;
  };

  return { nodePaint, nodePointerAreaPaint, linkPaint, nodeThreePaint };
};

export default useGraphPainter;
