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

/**
 * A value of the details drawer (one field of one operation) as readable text:
 * rich text (Content is html, Description is markdown) shows without its markup,
 * entities decoded, script and style removed; line breaks kept as single spaces.
 * The value is never cut: the table cell wraps it.
 */
export const toPlainHistoryValue = (value: string | null | undefined): string => {
  if (!value) return '';
  return value
    .replace(/<(script|style)[^>]*>[\s\S]*?<\/\1>/gi, ' ')
    .replace(HTML_TAG, ' ')
    .replace(/&(amp|lt|gt|quot|#39|apos|nbsp);/g, (entity) => HTML_ENTITIES[entity] ?? entity)
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1') // markdown links and images keep their text
    .replace(/^[ \t]*(#{1,6}|>|[-*+]|\d+\.)[ \t]+/gm, '') // markdown headings, quotes and list markers
    .replace(/(\*\*|~~|`+)/g, '') // markdown bold, strikethrough and code marks
    .replace(/\s+/g, ' ')
    .trim();
};
