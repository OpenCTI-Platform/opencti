import DOMPurify from 'dompurify';

/**
 * Parses user-written HTML safely for the PDF export.
 * The content is first sanitized with DOMPurify (scripts and event handlers such as `onerror` are removed), then
 * parsed into an inert document, separate from the live page, where nothing loads or runs. Assigning the raw markup
 * to the `innerHTML` of an element created from `document` would fire those handlers, a cross-site scripting risk.
 *
 * @param content The html content in string.
 * @returns The body of the inert document, to query and modify; read `innerHTML` on it to serialize it back.
 */
export const parseInertHtml = (content: string): HTMLElement => {
  return new DOMParser().parseFromString(DOMPurify.sanitize(content), 'text/html').body;
};
