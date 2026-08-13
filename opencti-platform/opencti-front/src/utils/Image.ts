import * as htmlToImage from 'html-to-image';
import fileDownload from 'js-file-download';
import pdfMake from 'pdfmake';
import isSvg from 'is-svg';
import { TDocumentDefinitions } from 'pdfmake/interfaces';

// html-to-image does not export its Options type from the package root, so it's derived here
// instead of reaching into an internal (non-public) import path.
type HtmlToImageOptions = NonNullable<Parameters<typeof htmlToImage.toPng>[1]>;

/**
 * MUI class names that are excluded from image/PDF exports by default.
 * Elements with these classes are filtered out unless explicitly marked with EXPORT_KEEP_CLASS.
 */
const ignoredClasses = [
  'MuiDialog-root',
  'MuiDrawer-docked',
  'MuiIconButton-root',
  'MuiInputBase-root',
];

/** CSS class to force a DOM node (and its descendants) to be included in exports. */
export const EXPORT_KEEP_CLASS = 'export-keep';

/** CSS class to force a DOM node (and its descendants) to be excluded from exports. */
export const EXPORT_REMOVE_CLASS = 'export-remove';

/**
 * apexcharts sets DOM attributes containing a colon on its chart legend, such as
 * `data:collapsed="false"` (pure internal bookkeeping for its own click/animation handling, never
 * read by CSS or by the browser's renderer). It declares the matching `xmlns:data="ApexChartsNS"`
 * namespace on its own chart `<svg>` root, which is valid as long as those attributes stay within
 * that SVG's subtree.
 *
 * Since v4.5.0, apexcharts renders its legend as a plain HTML sibling of that SVG instead of nesting
 * it inside the SVG's own `<foreignObject>` (a legitimate change, for PowerPoint/Word SVG-export
 * compatibility - see apexcharts.js#4014). That takes the `data:*`-attributed legend elements out of
 * the `xmlns:data` declaration's scope (XML namespace declarations only apply to the element they're
 * declared on and its descendants). html-to-image serializes the whole export tree with
 * XMLSerializer and embeds it as an SVG data URI to rasterize it: there, any such now-out-of-scope
 * colon-attribute is an undeclared XML namespace prefix, which makes the whole generated SVG
 * document fail to parse and load.
 *
 * Rather than removing these attributes, we declare the same namespace on the export root for the
 * duration of the export, which covers the legend too - nothing is ever removed from the DOM.
 */
const APEX_CHARTS_XML_NAMESPACE_ATTRIBUTE = 'xmlns:data';
const APEX_CHARTS_XML_NAMESPACE_VALUE = 'ApexChartsNS';

const declareApexChartsNamespace = (root: HTMLElement): (() => void) => {
  if (root.hasAttribute(APEX_CHARTS_XML_NAMESPACE_ATTRIBUTE)) {
    return () => {};
  }
  root.setAttribute(APEX_CHARTS_XML_NAMESPACE_ATTRIBUTE, APEX_CHARTS_XML_NAMESPACE_VALUE);
  return () => root.removeAttribute(APEX_CHARTS_XML_NAMESPACE_ATTRIBUTE);
};

/** Options shared by every html-to-image call used to export a dashboard/widget. */
const buildExportOptions = (
  backgroundColor: string | undefined,
  pixelRatio: number,
): HtmlToImageOptions => ({
  skipFonts: true,
  pixelRatio,
  backgroundColor,
  style: { margin: '0', paddingTop: '12px', paddingLeft: '12px' },
  imagePlaceholder: '', // ignore image fetch failure, and display empty area
  filter: isDomNodeKeptAtExport,
  onImageErrorHandler: () => {
    // We do nothing, it's just to avoid crashing export in case of image error.
  },
});

/** Common signature shared by html-to-image's toBlob and toPng. */
type HtmlToImageExportFn<T> = (node: HTMLElement, options?: HtmlToImageOptions) => Promise<T>;

/**
 * Runs an html-to-image export function against `container` with the apexcharts XML namespace
 * declared for the duration of the call (see declareApexChartsNamespace above), regardless of
 * success/failure.
 */
const runExport = async <T>(
  exportFn: HtmlToImageExportFn<T>,
  container: HTMLElement,
  options: HtmlToImageOptions,
): Promise<T> => {
  const undeclareApexChartsNamespace = declareApexChartsNamespace(container);
  try {
    return await exportFn(container, options);
  } finally {
    undeclareApexChartsNamespace();
  }
};

/**
 * Determines whether a DOM node should be included in the exported image/PDF.
 *
 * - If the node (or an ancestor) has the `export-keep` class → kept
 * - If the node (or an ancestor) has the `export-remove` class → removed
 * - If the node has one of the `ignoredClasses` → removed
 * - Otherwise → kept
 */
export const isDomNodeKeptAtExport = (domNode: HTMLElement): boolean => {
  if (domNode.closest?.(`.${EXPORT_KEEP_CLASS}`)) return true;
  if (domNode.closest?.(`.${EXPORT_REMOVE_CLASS}`)) return false;
  if (domNode.className) {
    for (const ignoredClass of ignoredClasses) {
      if (domNode.className.toString().includes(ignoredClass)) {
        return false;
      }
    }
  }
  return true;
};

export const exportImage = async (
  domElementId: string,
  currentWidth: number,
  currentHeight: number,
  name: string,
  backgroundColor: string | undefined,
  pixelRatio = 1,
  adjust: ((value: boolean) => void) | null = null,
): Promise<void> => {
  const container = document.getElementById(domElementId);
  if (!container) throw new Error(`Element #${domElementId} not found`);

  const options = buildExportOptions(backgroundColor, pixelRatio);
  const blob = await runExport(htmlToImage.toBlob, container, options);

  if (blob) {
    fileDownload(blob, `${name}.png`, 'image/png');
  }
  if (adjust) {
    container.setAttribute('style', `width:${currentWidth}px; height:${currentHeight}px;`);
    adjust(true);
  }
};

export const exportPdf = async (
  domElementId: string,
  name: string,
  backgroundColor: string | undefined,
  pixelRatio = 1,
  adjust: ((value: boolean) => void) | null = null,
): Promise<void> => {
  const container = document.getElementById(domElementId);
  if (!container) throw new Error(`Element #${domElementId} not found`);
  const { offsetWidth, offsetHeight } = container;
  const imageWidth = offsetWidth * pixelRatio;
  const imageHeight = offsetHeight * pixelRatio;

  const options = buildExportOptions(backgroundColor, pixelRatio);
  const image = await runExport(htmlToImage.toPng, container, options);

  const docDefinition: TDocumentDefinitions = {
    pageSize: {
      width: imageWidth,
      height: 'auto',
    },
    pageOrientation: 'portrait',
    pageMargins: [0, 0, 0, 0],
    background: () => ({
      canvas: [
        {
          type: 'rect',
          x: 0,
          y: 0,
          w: imageWidth,
          h: imageHeight,
          color: backgroundColor,
        },
      ],
    }),
    content: [
      {
        image,
        width: imageWidth,
        alignment: 'center',
      },
    ],
  };
  const pdf = pdfMake.createPdf(docDefinition);
  await pdf.download(`${name}.pdf`);
  if (adjust) {
    container.setAttribute('style', `width:${offsetWidth}px; height:${offsetHeight}px;`);
  }
};

export const getBase64ImageFromURL = async (url: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.setAttribute('crossOrigin', 'anonymous');

    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;

      const ctx = canvas.getContext('2d');
      if (!ctx) {
        reject(Error('No canvas ctx'));
        return;
      }

      ctx.drawImage(img, 0, 0);
      const dataURL = canvas.toDataURL('image/png');
      resolve(dataURL);
    };

    img.onerror = (error) => reject(error);
    img.src = url;
  });
};

interface SvgCheckResult {
  isSvg: boolean;
  content: string;
}

export const isImageFromUrlSvg = async (url: string): Promise<SvgCheckResult> => {
  const response = await fetch(url);
  const blob = await response.blob();
  const content = await blob.text();
  const imageIsSvg = isSvg(content);
  return {
    isSvg: imageIsSvg,
    content: imageIsSvg ? content : '',
  };
};
