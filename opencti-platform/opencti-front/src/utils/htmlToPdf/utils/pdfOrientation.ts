import { TIPTAP_EDITOR_SELECTOR, MAX_WIDTH_PORTRAIT } from './constants';

/**
 * Loop through elements inside the editor to determine if it is
 * necessary to generate a PDF in landscape or portrait.
 *
 * @returns 'landscape' or 'portrait'.
 */
const determineOrientation = () => {
  let pdfElementMaxWidth = 0;
  const elementEditor = document.querySelector(TIPTAP_EDITOR_SELECTOR);
  if (elementEditor) {
    // We need to get tables and img width inside the editor in order to choose orientation.
    // Tiptap uses <table>, CKEditor used figure.table
    const tables = Array.from(elementEditor.querySelectorAll('table, figure.table') ?? []);
    const images = Array.from(elementEditor.querySelectorAll('img') ?? []);
    [...tables, ...images].forEach((child) => {
      const width = (child as HTMLElement).clientWidth;
      if (width > pdfElementMaxWidth) {
        pdfElementMaxWidth = width;
      }
    });
  }
  return pdfElementMaxWidth > MAX_WIDTH_PORTRAIT
    ? 'landscape'
    : 'portrait';
};

export default determineOrientation;
