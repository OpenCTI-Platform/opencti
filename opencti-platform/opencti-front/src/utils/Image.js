import * as htmlToImage from 'html-to-image';
import fileDownload from 'js-file-download';
import pdfMake from 'pdfmake';
import isSvg from 'is-svg';

const ignoredClasses = [
  'MuiDialog-root',
  'MuiDrawer-docked',
  'MuiIconButton-root',
  'MuiInputBase-root',
];

export const exportImage = (
  domElementId,
  currentWidth,
  currentHeight,
  name,
  backgroundColor,
  pixelRatio = 1,
  adjust = null,
) => {
  const container = document.getElementById(domElementId);
  return new Promise((resolve, reject) => {
    htmlToImage
      .toBlob(container, {
        skipFonts: true,
        pixelRatio,
        backgroundColor,
        style: { margin: '0' },
        filter: (domNode) => {
          if (domNode.className) {
            for (const ignoredClass of ignoredClasses) {
              if (domNode.className.toString().includes(ignoredClass)) {
                return false;
              }
            }
          }
          return true;
        },
        onImageErrorHandler: () => {
          // We do nothing, it's just to avoid crashing export in case of image error.
        },
      })
      .then((blob) => {
        fileDownload(blob, `${name}.png`, 'image/png');
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

export const exportPdf = (
  domElementId,
  name,
  backgroundColor,
  pixelRatio = 1,
  adjust = null,
) => {
  const container = document.getElementById(domElementId);
  const { offsetWidth, offsetHeight } = container;
  const imageWidth = offsetWidth * pixelRatio;
  const imageHeight = offsetHeight * pixelRatio;
  return new Promise((resolve, reject) => {
    htmlToImage
      .toPng(container, {
        skipFonts: true,
        pixelRatio,
        backgroundColor,
        style: { margin: '0' },
        imagePlaceholder: '', // ignore image fetch failure, and display empty area
        filter: (domNode) => {
          if (domNode.className) {
            for (const ignoredClass of ignoredClasses) {
              if (domNode.className.toString().includes(ignoredClass)) {
                return false;
              }
            }
          }
          return true;
        },
        onImageErrorHandler: () => {
          // We do nothing, it's just to avoid crashing export in case of image error.
        },
      })
      .then((image) => {
        const docDefinition = {
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
        pdf.download(`${name}.pdf`);
        if (adjust) {
          container.setAttribute(
            'style',
            `width:${offsetWidth}px; height:${offsetHeight}px;`,
          );
        }
        resolve();
      })
      .catch((reason) => {
        reject(reason);
      });
  });
};

export const getBase64ImageFromURL = (url) => {
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

export const isImageFromUrlSvg = async (url) => {
  const response = await fetch(url);
  const blob = await response.blob();
  const content = await blob.text();
  const imageIsSvg = isSvg(content);
  return {
    isSvg: imageIsSvg,
    content: imageIsSvg ? content : '',
  };
};
