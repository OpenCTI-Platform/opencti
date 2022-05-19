import * as htmlToImage from 'html-to-image';
import fileDownload from 'js-file-download';
import pdfMake from 'pdfmake';

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
  backgroundColor = null,
  pixelRatio = 1,
  adjust = null,
) => {
  const container = document.getElementById(domElementId);
  return new Promise((resolve) => {
    htmlToImage
      .toBlob(container, {
        useCORS: true,
        allowTaint: true,
        pixelRatio,
        backgroundColor,
        style: { margin: 0 },
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
      });
  });
};

export const exportPdf = (
  domElementId,
  name,
  backgroundColor = null,
  pixelRatio = 1,
  adjust = null,
) => {
  const container = document.getElementById(domElementId);
  const { offsetWidth, offsetHeight } = container;
  const imageWidth = offsetWidth * pixelRatio;
  const imageHeight = offsetHeight * pixelRatio;
  return new Promise((resolve) => {
    htmlToImage
      .toPng(container, {
        useCORS: true,
        allowTaint: true,
        pixelRatio,
        backgroundColor,
        style: { margin: 0 },
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
      });
  });
};
