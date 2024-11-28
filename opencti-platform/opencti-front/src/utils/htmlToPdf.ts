import { renderToString } from 'react-dom/server';
import { compiler } from 'markdown-to-jsx';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake/build/pdfmake';
import { Content, TDocumentDefinitions } from 'pdfmake/interfaces';
import { APP_BASE_PATH } from '../relay/environment';
import { capitalizeWords, truncate } from './String';
import { dateFormat } from './Time';

const CKEDITOR_CONTAINER_SELECTOR = '.ck-content.ck-editor__editable.ck-editor__editable_inline';
const MAX_WIDTH_PORTRAIT = 680;

/**
 * NOT MEANT FOR EXPORT
 *
 * Loop through elements inside CKEditor to determine if it is
 * necessary to generate a PDF in landscape or portrait.
 *
 * @returns 'landscape' or 'portrait'.
 */
const determineOrientation = () => {
  let pdfElementMaxWidth = 0;
  const elementCkEditor = document.querySelector(CKEDITOR_CONTAINER_SELECTOR);
  if (elementCkEditor) {
    // We need to get tables and img width inside ckeditor in order to choose orientation.
    const tables = Array.from(elementCkEditor.querySelectorAll('figure.table') ?? []);
    const images = Array.from(elementCkEditor.querySelectorAll('img') ?? []);
    [...tables, ...images].forEach((child) => {
      if (child.clientWidth > pdfElementMaxWidth) {
        pdfElementMaxWidth = child.clientWidth;
      }
    });
  }
  return pdfElementMaxWidth > MAX_WIDTH_PORTRAIT
    ? 'landscape'
    : 'portrait';
};

/**
 * NOT MEANT FOR EXPORT
 *
 * @returns Roboto URLs for pdfmake.
 */
const robotoURLs = () => {
  const { protocol, hostname, port } = window.location;
  const url = `${protocol}//${hostname}:${port || ''}`;
  return {
    Roboto: {
      normal: `${url}${APP_BASE_PATH}/static/ext/Roboto-Regular.ttf`,
      bold: `${url}${APP_BASE_PATH}/static/ext/Roboto-Bold.ttf`,
      italics: `${url}${APP_BASE_PATH}/static/ext/Roboto-Italic.ttf`,
      bolditalics: `${url}${APP_BASE_PATH}/static/ext/Roboto-BoldItalic.ttf`,
    },
  };
};

/**
 * NOT MEANT FOR EXPORT
 *
 * Find images and apply a width in pixels on it.
 * We have several cases that can happened:
 * - An image with a width in pixels => nothing to do.
 * - An image with a width in percent => convert to pixels.
 * - An image inside a figure with a width in pixels => set width to image.
 * - An image inside a figure with a width in percent => convert to pixels and set to image.
 *
 * @param content The content of the file.
 * @returns New content with images widths in pixels.
 */
const setImagesWidth = (content: string) => {
  const elementCkEditor = document.querySelector(CKEDITOR_CONTAINER_SELECTOR);
  const fullWidth = elementCkEditor ? elementCkEditor.clientWidth : MAX_WIDTH_PORTRAIT;

  let updatedContent = content;
  // In case of images with percentage.
  updatedContent = updatedContent.replaceAll(/<img.+?style=".*?width:([0-9\\.]+%).*?".*?>/gi, (match, width) => {
    const widthValue = width.split('%')[0];
    const widthInPixels = (fullWidth * widthValue) / 100;
    return match.replace(width, `${widthInPixels}px`);
  });
  // In case of figures containing images, need to also apply the size on the image.
  updatedContent = updatedContent.replaceAll(/<figure.+?style=".*?width:([0-9\\.]+%).*?".*?>.*?<\/figure>/gi, (match, width) => {
    const widthValue = width.split('%')[0];
    const widthInPixels = (fullWidth * widthValue) / 100;
    return match.replace('<img src="', `<img width="${widthInPixels}" src="`);
  });
  // In case of figures with pixels containing images, need to also apply the size on the image.
  updatedContent = updatedContent.replaceAll(/<figure.+?style=".*?width:([0-9\\.]+px).*?".*?>.*?<\/figure>/gi, (match, width) => {
    const widthValue = width.split('px')[0];
    return match.replace('<img src="', `<img width="${widthValue}" src="`);
  });
  return updatedContent;
};

/**
 * NOT MEANT FOR EXPORT
 *
 * There are some tags we don't want in the generated PDF.
 *
 * @param content The content to analyse.
 * @returns Content without necessary stuff.
 */
const removeUselessContent = (content: string) => {
  return content
    .replaceAll('id="undefined" ', '') // ???
    .replaceAll(/<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi, ''); // Remove GIFs from content.
};

/**
 * NOT MEANT FOR EXPORT
 *
 * Generate a PDF that can be downloaded.
 *
 * @param pdfMakeObject Definition of the PDF to generate.
 * @param checkOrientation True if check content to determine PDF orientation.
 * @returns PDF ready to be downloaded.
 */
const generatePdf = (pdfMakeObject: TDocumentDefinitions, checkOrientation = false) => {
  const docDefinition = { ...pdfMakeObject };
  if (checkOrientation) {
    docDefinition.pageOrientation = determineOrientation();
  }
  return pdfMake.createPdf(docDefinition, undefined, robotoURLs());
};

/**
 * NOT MEANT FOR EXPORT
 *
 * Take tables and add an attribute to make them full width in PDF.
 *
 * @param content The html content in string.
 * @returns Same content but with new attribute on tables.
 */
const setTableFullWidth = (content: string) => {
  const container = document.createElement('div');
  container.innerHTML = content;
  container.querySelectorAll('table').forEach((table) => {
    const header = table.querySelector('thead tr');
    const body = table.querySelector('tbody tr');
    const element = header ?? body;
    if (element) {
      const nbColumns = element.querySelectorAll(header ? 'th' : 'td').length;
      if (nbColumns) {
        table.setAttribute('data-pdfmake', `{'widths':[${Array(nbColumns).fill("'*'").join()}]}`);
      }
    }
  });
  return container.innerHTML;
};

/**
 * NOT MEANT FOR EXPORT
 *
 * Convert ckeditor page breaks into ones for pdfmake.
 *
 * @param content The html content in string.
 * @returns Same content but with page breaks.
 */
const addPageBreaks = (content: string) => {
  const container = document.createElement('div');
  container.innerHTML = content;
  container.querySelectorAll('.page-break').forEach((pageBreak) => {
    const pageBreakNext = pageBreak.nextElementSibling;
    if (pageBreakNext) pageBreakNext.classList.add('pdf-pagebreak-before');
  });
  return container.innerHTML;
};

/**
 * Transform html file into a PDF that can be downloaded.
 *
 * @param fileName name of the file to transform.
 * @param content The content of the file.
 * @returns PDF object ready to be downloaded.
 */
export const htmlToPdf = (fileName: string, content: string) => {
  let htmlData = removeUselessContent(content);
  htmlData = setImagesWidth(htmlData);

  // Improve render for markdown files.
  if (fileName && fileName.endsWith('.md')) {
    htmlData = renderToString(compiler(htmlData, { wrapper: null }));
  }

  // Transform html string into a JS object that lib pdfmake can understand.
  const pdfMakeObject = htmlToPdfmake(htmlData, {
    imagesByReference: true,
    ignoreStyles: ['font-family'], // Ignoring fonts to force Roboto later.
  }) as unknown as TDocumentDefinitions; // Because wrong type when using imagesByReference: true.

  return generatePdf(pdfMakeObject);
};

/**
 * Transform html file into a PDF that can be downloaded.
 * /!\ Used for outcome templates reports.
 *
 * @param reportName Name the report outcome should have.
 * @param content HTML content.
 * @param templateName Name of the template used for PDF generation.
 * @param markingNames Markings of the outcome report.
 * @returns PDF object ready to be downloaded.
 */
export const htmlToPdfReport = (reportName: string, content: string, templateName: string, markingNames: string[]) => {
  let htmlData = removeUselessContent(content);
  htmlData = setImagesWidth(htmlData);
  htmlData = setTableFullWidth(htmlData);
  htmlData = addPageBreaks(htmlData);

  // Transform html string into a JS object that lib pdfmake can understand.
  const pdfMakeObject = htmlToPdfmake(htmlData, {
    imagesByReference: true,
    ignoreStyles: ['font-family'], // Ignoring fonts to force Roboto later.
    defaultStyles: {
      h2: { margin: [0, 20] },
      h3: { margin: [0, 20] },
    },
  }) as unknown as TDocumentDefinitions; // Because wrong type when using imagesByReference: true.

  const date = dateFormat(new Date()) ?? '';
  const formattedTemplateName = capitalizeWords(templateName);
  const truncatedTemplateName = truncate(formattedTemplateName, 25, false);

  const docDefinition: TDocumentDefinitions = {
    pageMargins: [50, 70],
    styles: {
      firstPageTitle: { fontSize: 26, bold: true },
      firstPageSubtitle: { fontSize: 20, marginTop: 6, marginLeft: 40 },
      firstPageDate: { fontSize: 14, bold: true, opacity: 0.7, marginTop: 15 },
      headerFooter: { opacity: 0.5 },
    },
    ...pdfMakeObject,
    content: [
      {
        absolutePosition: { x: 50, y: 60 },
        color: 'white',
        columns: [
          {
            width: 250,
            stack: [
              {
                text: formattedTemplateName,
                style: 'firstPageTitle',
              },
              {
                text: `Exported: ${date}`,
                style: 'firstPageDate',
              },
            ],
          },
          {
            text: reportName,
            alignment: 'right',
            style: 'firstPageSubtitle',
          },
        ],
      },
      {
        text: '',
        margin: [0, 240, 0, 0],
      },
      ...(pdfMakeObject.content as Content[]),
    ],
    background(currentPage, pageSize) {
      return {
        canvas: currentPage > 1
          ? []
          : [{
            type: 'rect',
            x: 0,
            y: 0,
            w: pageSize.width,
            h: pageSize.height / 3,
            color: '#0019ce',
          }],
      };
    },
    header(currentPage) {
      if (currentPage === 1) return [];
      return {
        style: 'headerFooter',
        margin: [50, 40, 50, 0],
        columns: [
          {
            text: truncate(reportName, 20, false),
            alignment: 'left',
          },
          {
            text: markingNames.join(', '),
            alignment: 'center',
          },
          {
            text: date,
            alignment: 'right',
          },
        ],
      };
    },
    footer(currentPage, pageCount) {
      return {
        style: 'headerFooter',
        margin: [50, 40, 50, 0],
        columns: [
          {
            text: truncatedTemplateName,
            alignment: 'left',
          },
          {
            text: markingNames.join(', '),
            alignment: 'center',
          },
          {
            text: `${currentPage} / ${pageCount}`,
            alignment: 'right',
          },
        ],
      };
    },
    pageBreakBefore(currentNode) {
      if (!currentNode.style) return false;
      if (typeof currentNode.style !== 'string' && !Array.isArray(currentNode.style)) return false;
      return currentNode.style.includes('pdf-pagebreak-before');
    },
  };

  return generatePdf(docDefinition);
};
