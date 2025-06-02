import type { Options } from './types';

export function resolveUrl(url: string, baseUrl: string | null): string {
  // url is absolute already
  if (url.match(/^[a-z]+:\/\//i)) {
    return url;
  }

  // url is absolute already, without protocol
  if (url.match(/^\/\//)) {
    return window.location.protocol + url;
  }

  // dataURI, mailto:, tel:, etc.
  if (url.match(/^[a-z]+:/i)) {
    return url;
  }

  const doc = document.implementation.createHTMLDocument();
  const base = doc.createElement('base');
  const a = doc.createElement('a');

  doc.head.appendChild(base);
  doc.body.appendChild(a);

  if (baseUrl) {
    base.href = baseUrl;
  }

  a.href = url;

  return a.href;
}

export const uuid = (() => {
  // generate uuid for className of pseudo elements.
  // We should not use GUIDs, otherwise pseudo elements sometimes cannot be captured.
  let counter = 0;

  // ref: http://stackoverflow.com/a/6248722/2519373
  const random = () =>
    // eslint-disable-next-line no-bitwise
    `0000${((Math.random() * 36 ** 4) << 0).toString(36)}`.slice(-4);

  return () => {
    counter += 1;
    return `u${random()}${counter}`;
  };
})();

export function delay<T>(ms: number) {
  return (args: T) => new Promise<T>((resolve) => {
    setTimeout(() => resolve(args), ms);
  });
}

export function toArray<T>(arrayLike: any): T[] {
  const arr: T[] = [];

  for (let i = 0, l = arrayLike.length; i < l; i++) {
    arr.push(arrayLike[i]);
  }

  return arr;
}

let styleProps: string[] | null = null;
export function getStyleProperties(options: Options = {}): string[] {
  if (styleProps) {
    return styleProps;
  }

  if (options.includeStyleProperties) {
    styleProps = options.includeStyleProperties;
    return styleProps;
  }

  styleProps = toArray(window.getComputedStyle(document.documentElement));

  return styleProps;
}

function px(node: HTMLElement, styleProperty: string) {
  const win = node.ownerDocument.defaultView || window;
  const val = win.getComputedStyle(node).getPropertyValue(styleProperty);
  return val ? parseFloat(val.replace('px', '')) : 0;
}

function getNodeWidth(node: HTMLElement) {
  const leftBorder = px(node, 'border-left-width');
  const rightBorder = px(node, 'border-right-width');
  return node.clientWidth + leftBorder + rightBorder;
}

function getNodeHeight(node: HTMLElement) {
  const topBorder = px(node, 'border-top-width');
  const bottomBorder = px(node, 'border-bottom-width');
  return node.clientHeight + topBorder + bottomBorder;
}

export function getImageSize(targetNode: HTMLElement, options: Options = {}) {
  const width = options.width || getNodeWidth(targetNode);
  const height = options.height || getNodeHeight(targetNode);

  return { width, height };
}

export function getPixelRatio() {
  let ratio;

  let FINAL_PROCESS;
  try {
    FINAL_PROCESS = process;
  } catch (e) {
    // pass
  }

  const val = FINAL_PROCESS && FINAL_PROCESS.env
    ? FINAL_PROCESS.env.devicePixelRatio
    : null;
  if (val) {
    ratio = parseInt(val, 10);
    if (Number.isNaN(ratio)) {
      ratio = 1;
    }
  }
  return ratio || window.devicePixelRatio || 1;
}

// @see https://developer.mozilla.org/en-US/docs/Web/HTML/Element/canvas#maximum_canvas_size
const canvasDimensionLimit = 16384;

export function checkCanvasDimensions(canvas: HTMLCanvasElement) {
  if (
    canvas.width > canvasDimensionLimit
    || canvas.height > canvasDimensionLimit
  ) {
    if (
      canvas.width > canvasDimensionLimit
      && canvas.height > canvasDimensionLimit
    ) {
      if (canvas.width > canvas.height) {
        canvas.height *= canvasDimensionLimit / canvas.width;
        canvas.width = canvasDimensionLimit;
      } else {
        canvas.width *= canvasDimensionLimit / canvas.height;
        canvas.height = canvasDimensionLimit;
      }
    } else if (canvas.width > canvasDimensionLimit) {
      canvas.height *= canvasDimensionLimit / canvas.width;
      canvas.width = canvasDimensionLimit;
    } else {
      canvas.width *= canvasDimensionLimit / canvas.height;
      canvas.height = canvasDimensionLimit;
    }
  }
}

export function canvasToBlob(
  canvas: HTMLCanvasElement,
  options: Options = {},
): Promise<Blob | null> {
  if (canvas.toBlob) {
    return new Promise((resolve) => {
      canvas.toBlob(
        resolve,
        options.type ? options.type : 'image/png',
        options.quality ? options.quality : 1,
      );
    });
  }

  return new Promise((resolve) => {
    const binaryString = window.atob(
      canvas
        .toDataURL(
          options.type ? options.type : undefined,
          options.quality ? options.quality : undefined,
        )
        .split(',')[1],
    );
    const len = binaryString.length;
    const binaryArray = new Uint8Array(len);

    for (let i = 0; i < len; i += 1) {
      binaryArray[i] = binaryString.charCodeAt(i);
    }

    resolve(
      new Blob([binaryArray], {
        type: options.type ? options.type : 'image/png',
      }),
    );
  });
}

export function createImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    console.log('ANGIE - createImage 1');
    const img = new Image();
    console.log('ANGIE - createImage 2');
    img.onload = () => {
      console.log('ANGIE - createImage 2.1');
      img.decode().then(() => {
        requestAnimationFrame(() => resolve(img));
      }).catch((reason) => {
        console.log('ANGIE error:', JSON.stringify(reason, ['message', 'arguments', 'type', 'name']));
      });
      console.log('ANGIE - createImage 2.2');
    };
    console.log('ANGIE - createImage 3');
    img.onerror = (reason) => console.log('ANGIE ERROR - createImage 3', JSON.stringify(reason, ['message', 'arguments', 'type', 'name']));
    img.crossOrigin = 'anonymous';
    img.decoding = 'async';
    img.src = url;
    console.log('ANGIE - createImage 4', img);
  });
}

export async function svgToDataURL(svg: SVGElement): Promise<string> {
  return Promise.resolve()
    .then(() => new XMLSerializer().serializeToString(svg))
    .then(encodeURIComponent)
    .then((html) => `data:image/svg+xml;charset=utf-8,${html}`);
}

export async function nodeToDataURL(
  node: HTMLElement,
  width: number,
  height: number,
): Promise<string> {
  const xmlns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(xmlns, 'svg');
  const foreignObject = document.createElementNS(xmlns, 'foreignObjectDebug');

  svg.setAttribute('width', `${width}`);
  svg.setAttribute('height', `${height}`);
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);

  foreignObject.setAttribute('width', '100%');
  foreignObject.setAttribute('height', '100%');
  foreignObject.setAttribute('x', '0');
  foreignObject.setAttribute('y', '0');
  // foreignObject.setAttribute('externalResourcesRequired', 'true');

  svg.appendChild(foreignObject);
  foreignObject.appendChild(node);
  return svgToDataURL(svg);
}

export const isInstanceOfElement = <
  T extends typeof Element | typeof HTMLElement | typeof SVGImageElement,
>(
    node: Element | HTMLElement | SVGImageElement,
    instance: T,
  ): node is T['prototype'] => {
  if (node instanceof instance) return true;

  const nodePrototype = Object.getPrototypeOf(node);

  if (nodePrototype === null) return false;

  return (
    nodePrototype.constructor.name === instance.name
    || isInstanceOfElement(nodePrototype, instance)
  );
};
