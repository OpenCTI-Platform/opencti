import { Node } from 'pdfmake/interfaces';

/**
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

export const pdfPageBreaks = (currentNode: Node) => {
  if (!currentNode.style) return false;
  if (typeof currentNode.style !== 'string' && !Array.isArray(currentNode.style)) return false;
  return currentNode.style.includes('pdf-pagebreak-before');
};

export default addPageBreaks;
