import * as htmlToImage from 'html-to-image';
import fileDownload from 'js-file-download';
import pdfMake from 'pdfmake';
import isSvg from 'is-svg';
import { TDocumentDefinitions } from 'pdfmake/interfaces';

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
  if (!container) return Promise.reject(new Error(`Element #${domElementId} not found`));
  return new Promise((resolve, reject) => {
    htmlToImage
      .toBlob(container, {
        skipFonts: true,
        pixelRatio,
        backgroundColor,
        style: { margin: '0', paddingTop: '12px', paddingLeft: '12px' },
        filter: isDomNodeKeptAtExport,
        onImageErrorHandler: () => {
          // We do nothing, it's just to avoid crashing export in case of image error.
        },
      })
      .then((blob) => {
        if (blob) {
          fileDownload(blob, `${name}.png`, 'image/png');
        }
        if (adjust) {
          container.setAttribute(
            'style',
            `width:${currentWidth}px; height:${currentHeight}px;`,
          );
          adjust(true);
        }
        resolve();
      }).catch((reason) => {
        reject(reason);
      });
  });
};

export const exportPdf = async (
  domElementId: string,
  name: string,
  backgroundColor: string | undefined,
  pixelRatio = 1,
  adjust: ((value: boolean) => void) | null = null,
): Promise<void> => {
  const container = document.getElementById(domElementId);
  if (!container) return Promise.reject(new Error(`Element #${domElementId} not found`));
  const { offsetWidth, offsetHeight } = container;
  const imageWidth = offsetWidth * pixelRatio;
  const imageHeight = offsetHeight * pixelRatio;
  return new Promise((resolve, reject) => {
    htmlToImage
      .toPng(container, {
        skipFonts: true,
        pixelRatio,
        backgroundColor,
        style: { margin: '0', paddingTop: '12px', paddingLeft: '12px' },
        imagePlaceholder: '', // ignore image fetch failure, and display empty area
        filter: isDomNodeKeptAtExport,
        onImageErrorHandler: () => {
          // We do nothing, it's just to avoid crashing export in case of image error.
        },
      })
      .then((image) => {
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
        pdf.download(`${name}.pdf`).then(() => {
          if (adjust) {
            container.setAttribute(
              'style',
              `width:${offsetWidth}px; height:${offsetHeight}px;`,
            );
          }
          resolve();
        });
      })
      .catch((reason) => {
        reject(reason);
      });
  });
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
