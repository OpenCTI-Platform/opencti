import { TIPTAP_EDITOR_SELECTOR, CKEDITOR_CONTAINER_SELECTOR, MAX_WIDTH_PORTRAIT } from './constants';

/**
 * Loop through elements inside the editor to determine if it is
 * necessary to generate a PDF in landscape or portrait.
 *
 * @returns 'landscape' or 'portrait'.
 */
const determineOrientation = (isTiptapEnabled = false) => {
  let pdfElementMaxWidth = 0;
  const selector = isTiptapEnabled ? TIPTAP_EDITOR_SELECTOR : CKEDITOR_CONTAINER_SELECTOR;
  const elementEditor = document.querySelector(selector);
  if (elementEditor) {
    // We need to get tables and img width inside the editor in order to choose orientation.
    // Tiptap uses <table>, legacy editor used figure.table
    const tableSelector = isTiptapEnabled ? 'table, figure.table' : 'figure.table';
    const tables = Array.from(elementEditor.querySelectorAll(tableSelector) ?? []);
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
