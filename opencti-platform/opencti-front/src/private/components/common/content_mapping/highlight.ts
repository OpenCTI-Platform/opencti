// Highlighting of the mapped / suggested values in the document. Only text is touched, never
// attributes: a value contained in a link URL no longer breaks the link (#12539).

export type HighlightStatus = 'mapped' | 'suggested' | 'new';

export interface HighlightTerm {
  key: string;
  text: string;
  status: HighlightStatus;
  color: string;
}

export interface TextPart {
  text: string;
  term?: HighlightTerm;
}

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Longest values first, so that "Fast Reverse Proxy (FRP)" wins over "FRP"; a value is only
// matched as a whole word, so that "CIA" is not found in "CIAFBI".
export const buildMatcher = (terms: HighlightTerm[]) => {
  const byText = new Map<string, HighlightTerm>();
  terms.forEach((term) => {
    const text = term.text.trim().toLowerCase();
    if (text.length > 1 && !byText.has(text)) byText.set(text, term);
  });
  if (byText.size === 0) return null;
  const alternatives = [...byText.keys()].sort((a, b) => b.length - a.length).map(escapeRegExp);
  return {
    regexp: new RegExp(`(?<![\\p{L}\\p{N}_])(${alternatives.join('|')})(?![\\p{L}\\p{N}_])`, 'giu'),
    termOf: (match: string) => byText.get(match.toLowerCase()),
  };
};

export const splitText = (text: string, matcher: ReturnType<typeof buildMatcher>): TextPart[] => {
  if (!matcher) return [{ text }];
  const parts: TextPart[] = [];
  let last = 0;
  for (const match of text.matchAll(matcher.regexp)) {
    const index = match.index ?? 0;
    if (index > last) parts.push({ text: text.slice(last, index) });
    parts.push({ text: match[0], term: matcher.termOf(match[0]) });
    last = index + match[0].length;
  }
  if (last < text.length) parts.push({ text: text.slice(last) });
  return parts;
};

export const MARK_SELECTOR = 'mark[data-cm-key]';

const createMark = (doc: Document, part: TextPart) => {
  const mark = doc.createElement('mark');
  mark.textContent = part.text;
  mark.dataset.cmKey = part.term!.key;
  mark.dataset.cmStatus = part.term!.status;
  mark.style.setProperty('--cm-color', part.term!.color);
  return mark;
};

// Wraps every occurrence in a <mark data-cm-key>; returns the number of occurrences per key.
export const highlightElement = (root: HTMLElement, terms: HighlightTerm[]): Record<string, number> => {
  const counts: Record<string, number> = {};
  const matcher = buildMatcher(terms);
  if (!matcher) return counts;
  const walker = root.ownerDocument.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => (node.parentElement?.closest(`${MARK_SELECTOR}, script, style`)
      ? NodeFilter.FILTER_REJECT
      : NodeFilter.FILTER_ACCEPT),
  });
  const textNodes: Text[] = [];
  while (walker.nextNode()) textNodes.push(walker.currentNode as Text);
  textNodes.forEach((node) => {
    const parts = splitText(node.data, matcher);
    if (!parts.some((part) => part.term)) return;
    const fragment = root.ownerDocument.createDocumentFragment();
    parts.forEach((part) => {
      if (part.term) {
        counts[part.term.key] = (counts[part.term.key] ?? 0) + 1;
        fragment.appendChild(createMark(root.ownerDocument, part));
      } else {
        fragment.appendChild(root.ownerDocument.createTextNode(part.text));
      }
    });
    node.replaceWith(fragment);
  });
  return counts;
};

export const clearHighlights = (root: HTMLElement) => {
  root.querySelectorAll(MARK_SELECTOR).forEach((mark) => mark.replaceWith(mark.ownerDocument.createTextNode(mark.textContent ?? '')));
  root.normalize();
};

const escapeHtml = (value: string) => value
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');

// Same marks as HTML, for the text layer of PDF pages (react-pdf customTextRenderer).
export const highlightToHtml = (text: string, matcher: ReturnType<typeof buildMatcher>) => splitText(text, matcher)
  .map((part) => (part.term
    ? `<mark data-cm-key="${escapeHtml(part.term.key)}" data-cm-status="${part.term.status}" style="--cm-color:${escapeHtml(part.term.color)}">${escapeHtml(part.text)}</mark>`
    : escapeHtml(part.text)))
  .join('');
