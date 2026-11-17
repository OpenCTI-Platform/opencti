const HTML_TAG = /<\/?[a-z][^>]*>/gi;
const HTML_ENTITIES: Record<string, string> = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': '\'', '&apos;': '\'', '&nbsp;': ' ' };

/**
 * A history message is one line of markdown whose values sit in inline code spans.
 * Messages stored before the generator produced plain text can carry html tags and
 * line breaks inside a value: a line break ends the code span and opens a new paragraph,
 * and the tags then show raw. Reduce such a message to one line of plain text values
 * so every stored message renders as a single clean line.
 */
export const toSingleLineHistoryMessage = (message: string | null | undefined): string => {
  if (!message) return '';
  return message
    .replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(HTML_TAG, ' ')
    .replace(/&(amp|lt|gt|quot|#39|apos|nbsp);/g, (entity) => HTML_ENTITIES[entity] ?? entity)
    .replace(/\s+/g, ' ')
    .trim();
};
