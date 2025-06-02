import { Options } from './types';
import { cloneNode } from './clone-node';
import { embedImages } from './embed-images';
import { applyStyle } from './apply-style';
import { embedWebFonts, getWebFontCSS } from './embed-webfonts';
import { getImageSize, getPixelRatio, createImage, canvasToBlob, nodeToDataURL, checkCanvasDimensions } from './util';

export async function toSvg<T extends HTMLElement>(
  node: T,
  options: Options = {},
): Promise<string> {
  const { width, height } = getImageSize(node, options);
  const clonedNode = (await cloneNode(node, options, true)) as HTMLElement;
  await embedWebFonts(clonedNode, options);
  await embedImages(clonedNode, options);
  applyStyle(clonedNode, options);
  const datauri = await nodeToDataURL(clonedNode, width, height);
  return datauri;
}

export async function toCanvas<T extends HTMLElement>(
  node: T,
  options: Options = {},
): Promise<HTMLCanvasElement> {
  console.log('ANGIE - toCanvas 1');
  const { width, height } = getImageSize(node, options);
  console.log('ANGIE - toCanvas 1.1');
  const svg = await toSvg(node, options);
  console.log('ANGIE - toCanvas 1.2', svg);
  const img = await createImage(svg).catch((onReject) => console.log('REJECT', JSON.stringify(onReject)));
  console.log('ANGIE - toCanvas 2', img);
  const canvas = document.createElement('canvas');
  console.log('ANGIE - toCanvas 3');
  const context = canvas.getContext('2d')!;
  console.log('ANGIE - toCanvas 4');
  const ratio = options.pixelRatio || getPixelRatio();
  console.log('ANGIE - toCanvas 5');
  const canvasWidth = options.canvasWidth || width;
  const canvasHeight = options.canvasHeight || height;

  canvas.width = canvasWidth * ratio;
  canvas.height = canvasHeight * ratio;
  console.log('ANGIE - toCanvas 6');
  if (!options.skipAutoScale) {
    checkCanvasDimensions(canvas);
  }
  canvas.style.width = `${canvasWidth}`;
  canvas.style.height = `${canvasHeight}`;
  console.log('ANGIE - toCanvas 7');
  if (options.backgroundColor) {
    context.fillStyle = options.backgroundColor;
    context.fillRect(0, 0, canvas.width, canvas.height);
  }
  console.log('ANGIE - toCanvas 8');
  context.drawImage(img, 0, 0, canvas.width, canvas.height);
  console.log('ANGIE - toCanvas FIN');
  return canvas;
}

export async function toPixelData<T extends HTMLElement>(
  node: T,
  options: Options = {},
): Promise<Uint8ClampedArray> {
  const { width, height } = getImageSize(node, options);
  const canvas = await toCanvas(node, options);
  const ctx = canvas.getContext('2d')!;
  return ctx.getImageData(0, 0, width, height).data;
}

export async function toPng<T extends HTMLElement>(
  node: T,
  options: Options = {},
): Promise<string> {
  const canvas = await toCanvas(node, options);
  return canvas.toDataURL();
}

export async function toJpeg<T extends HTMLElement>(
  node: T,
  options: Options = {},
): Promise<string> {
  const canvas = await toCanvas(node, options);
  return canvas.toDataURL('image/jpeg', options.quality || 1);
}

export async function toBlobDebug<T extends HTMLElement>(
  node: T,
  options: Options = {},
): Promise<Blob | null> {
  const canvas = await toCanvas(node, options);
  const blob = await canvasToBlob(canvas);
  return blob;
}

export async function getFontEmbedCSS<T extends HTMLElement>(
  node: T,
  options: Options = {},
): Promise<string> {
  return getWebFontCSS(node, options);
}
