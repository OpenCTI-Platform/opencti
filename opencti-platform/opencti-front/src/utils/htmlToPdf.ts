import { renderToString } from 'react-dom/server';
import { compiler } from 'markdown-to-jsx';
import htmlToPdfmake from 'html-to-pdfmake';
import pdfMake from 'pdfmake/build/pdfmake';
import { TDocumentDefinitions } from 'pdfmake/interfaces';
import { APP_BASE_PATH } from '../relay/environment';

const CKEDITOR_CONTAINER_SELECTOR = '.ck-content.ck-editor__editable.ck-editor__editable_inline';
const MAX_WIDTH_PORTRAIT = 680;

/**
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
 * Transform html file into a PDF that can be downloaded.
 *
 * @param fileName name of the file to transform.
 * @param content The content of the file.
 * @returns PDF object ready to be downloaded.
 */
const htmlToPdf = (fileName: string, content: string) => {
  // Remove some content we don't want in the PDF.
  let htmlData = content
    .replaceAll('id="undefined" ', '') // ???
    .replaceAll(/<img[^>]+src=(\\?["'])[^'"]+\.gif\1[^>]*\/?>/gi, ''); // Remove GIFs from content.

  // Replace images in percentage with pixels.
  htmlData = setImagesWidth(htmlData);

  // Improve render for markdown files.
  if (fileName.endsWith('.md')) {
    htmlData = renderToString(compiler(htmlData, { wrapper: null }));
  }

  // Transform html string into a JS object that lib pdfmake can understand.
  const pdfMakeObject = htmlToPdfmake(htmlData, {
    imagesByReference: true,
    ignoreStyles: ['font-family'], // Ignoring fonts to force Roboto later.
  }) as unknown as TDocumentDefinitions; // Because wrong type when using imagesByReference: true.

  // Generate a PDF that can be opened or downloaded.
  return pdfMake.createPdf(
    {
      ...pdfMakeObject,
      pageOrientation: determineOrientation(),
    },
    undefined,
    robotoURLs(),
  );
};

export default htmlToPdf;
