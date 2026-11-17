/**
 * Parses user-written HTML into an inert document, separate from the live page: nothing in it loads or runs
 * (no image request, no event handler such as `onerror`, no script). Assigning the same markup to the
 * `innerHTML` of an element created from `document` would fire those handlers, a cross-site scripting risk.
 *
 * @param content The html content in string.
 * @returns The body of the inert document, to query and modify; read `innerHTML` on it to serialize it back.
 */
export const parseInertHtml = (content: string): HTMLElement => {
  return new DOMParser().parseFromString(content, 'text/html').body;
};
