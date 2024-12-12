import { CKEDITOR_CONTAINER_SELECTOR, MAX_WIDTH_PORTRAIT } from './constants';

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

export default determineOrientation;
