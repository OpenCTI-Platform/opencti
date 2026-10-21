import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { Document, Page } from 'react-pdf';
import 'react-pdf/dist/Page/TextLayer.css';
import { Box } from '@mui/material';
import { alpha, useTheme } from '@mui/material/styles';
import { APP_BASE_PATH } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import '../../../../utils/pdfWorker-setup';
import { buildMatcher, highlightElement, highlightToHtml, HighlightTerm, MARK_SELECTOR } from './highlight';

export interface MappingSource {
  id: string;
  label: string;
  // 'main' is the description and content of the container; the others are attached files.
  kind: 'main' | 'markdown' | 'text' | 'html' | 'pdf';
}

export const sourceKindOf = (mimetype: string | null | undefined): MappingSource['kind'] | null => {
  if (mimetype === 'application/pdf') return 'pdf';
  if (mimetype === 'text/markdown') return 'markdown';
  if (mimetype === 'text/html') return 'html';
  if (mimetype === 'text/plain') return 'text';
  return null;
};

export interface TextSelection {
  text: string;
  rect: DOMRect;
  // The sentence around the selection, kept as evidence for a relationship.
  passage: string;
}

interface ContentMappingDocumentProps {
  source: MappingSource;
  title?: string | null;
  description?: string | null;
  contentHtml?: string | null;
  terms: HighlightTerm[];
  activeKeys: string[];
  selectedKeys: string[];
  onHoverKey: (key: string | null, rect?: DOMRect) => void;
  onClickKey: (key: string) => void;
  onSelectText: (selection: TextSelection) => void;
  onCounts: (counts: Record<string, number>) => void;
  // Plain text of the displayed document, to find the passages that support a relationship.
  onText?: (text: string) => void;
}

const sanitize = (html: string) => DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });

const markdownToHtml = (markdown: string) => sanitize(marked.parse(markdown, { async: false }) as string);

const sentenceAround = (node: Node | null, text: string) => {
  const blockText = (node?.parentElement?.closest('p, li, td, div, span') ?? node?.parentElement)?.textContent ?? text;
  const index = blockText.indexOf(text);
  if (index < 0) return text;
  const start = Math.max(blockText.lastIndexOf('.', index) + 1, 0);
  const end = blockText.indexOf('.', index + text.length);
  return blockText.slice(start, end < 0 ? undefined : end + 1).trim();
};

const useFileText = (source: MappingSource) => {
  const [text, setText] = useState<string | null>(null);
  useEffect(() => {
    if (source.kind === 'main' || source.kind === 'pdf') return undefined;
    let cancelled = false;
    setText(null);
    fetch(`${APP_BASE_PATH}/storage/view/${encodeURIComponent(source.id)}`, { credentials: 'include' })
      .then((response) => response.text())
      .then((content) => {
        if (!cancelled) setText(content);
      });
    return () => {
      cancelled = true;
    };
  }, [source.id, source.kind]);
  return text;
};

const ContentMappingDocument = ({
  source, title, description, contentHtml, terms, activeKeys, selectedKeys, onHoverKey, onClickKey, onSelectText, onCounts, onText,
}: ContentMappingDocumentProps) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const ref = useRef<HTMLDivElement>(null);
  const fileText = useFileText(source);
  const [pageCount, setPageCount] = useState(0);
  const matcher = useMemo(() => buildMatcher(terms), [terms]);
  // Stable renderer: a new one makes react-pdf render the text layer again, which reports the counts again.
  const pdfTextRenderer = useCallback(({ str }: { str: string }) => highlightToHtml(str, matcher), [matcher]);
  const lastCounts = useRef('');
  const reportCounts = (counts: Record<string, number>) => {
    const serialized = JSON.stringify(counts);
    if (serialized === lastCounts.current) return;
    lastCounts.current = serialized;
    onCounts(counts);
  };

  // The document is rendered as static HTML outside of React, so that marks can be inserted in it.
  const html = useMemo(() => {
    if (source.kind === 'main') {
      return [description ? markdownToHtml(description) : '', contentHtml ? sanitize(contentHtml) : ''].filter(Boolean).join('<hr/>');
    }
    if (fileText === null) return null;
    if (source.kind === 'markdown') return markdownToHtml(fileText);
    if (source.kind === 'html') return sanitize(fileText);
    if (source.kind === 'text') return `<pre>${DOMPurify.sanitize(fileText.replace(/</g, '&lt;'))}</pre>`;
    return null;
  }, [source.kind, description, contentHtml, fileText]);

  useEffect(() => {
    const root = ref.current?.querySelector<HTMLElement>('[data-cm-html]');
    if (!root || html === null) return;
    root.innerHTML = html;
    reportCounts(highlightElement(root, terms));
    onText?.(root.textContent ?? '');
  }, [html, terms]);

  // PDF: marks come from the text layer renderer, counted once all pages are rendered.
  const countPdfMarks = () => {
    const counts: Record<string, number> = {};
    ref.current?.querySelectorAll<HTMLElement>(MARK_SELECTOR).forEach((mark) => {
      const key = mark.dataset.cmKey!;
      counts[key] = (counts[key] ?? 0) + 1;
    });
    reportCounts(counts);
    onText?.(ref.current?.textContent ?? '');
  };

  useEffect(() => {
    ref.current?.querySelectorAll<HTMLElement>(MARK_SELECTOR).forEach((mark) => {
      mark.classList.toggle('cm-active', activeKeys.includes(mark.dataset.cmKey!));
      mark.classList.toggle('cm-selected', selectedKeys.includes(mark.dataset.cmKey!));
    });
    if (activeKeys.length > 0) {
      ref.current?.querySelector(`${MARK_SELECTOR}.cm-active`)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  });

  const markOf = (target: EventTarget | null) => (target instanceof HTMLElement ? target.closest<HTMLElement>(MARK_SELECTOR) : null);

  const handleMouseUp = () => {
    const selection = window.getSelection();
    const text = selection?.toString().trim() ?? '';
    if (!selection || selection.rangeCount === 0 || text.length < 2 || text.length > 300) return;
    const range = selection.getRangeAt(0);
    if (!ref.current?.contains(range.commonAncestorContainer)) return;
    onSelectText({ text, rect: range.getBoundingClientRect(), passage: sentenceAround(selection.anchorNode, text) });
  };

  const color = (status: string) => `& mark[data-cm-status="${status}"]`;
  return (
    <Box
      ref={ref}
      onMouseUp={handleMouseUp}
      onMouseOver={(event) => {
        const mark = markOf(event.target);
        if (mark) onHoverKey(mark.dataset.cmKey!, mark.getBoundingClientRect());
      }}
      onMouseOut={(event) => {
        if (markOf(event.target) && !markOf(event.relatedTarget)) onHoverKey(null);
      }}
      onClick={(event) => {
        const mark = markOf(event.target);
        if (mark && !window.getSelection()?.toString()) onClickKey(mark.dataset.cmKey!);
      }}
      sx={{
        flex: 1,
        minHeight: 0,
        overflowY: 'auto',
        lineHeight: 1.75,
        fontSize: 15,
        color: theme.palette.text.primary,
        '& h1, & h2, & h3': { lineHeight: 1.3 },
        '& pre': { whiteSpace: 'pre-wrap', fontFamily: 'inherit' },
        '& mark[data-cm-key]': {
          backgroundColor: 'transparent',
          color: 'var(--cm-color)',
          fontWeight: 600,
          textDecorationLine: 'underline',
          textDecorationColor: 'var(--cm-color)',
          textDecorationThickness: '2px',
          textUnderlineOffset: '3px',
          textDecorationSkipInk: 'none',
          cursor: 'pointer',
          borderRadius: '2px',
        },
        // Distinct line styles: the status does not rely on color alone.
        [color('mapped')]: { textDecorationStyle: 'solid' },
        [color('suggested')]: { textDecorationStyle: 'dashed' },
        [color('new')]: { textDecorationStyle: 'wavy' },
        '& mark.cm-active': { backgroundColor: alpha(theme.palette.primary.main, 0.25) },
        '& mark.cm-selected': { outline: '1.5px solid var(--cm-color)', outlineOffset: '1px' },
        // react-pdf text layer: keep the glyphs transparent but show the marks.
        '& .textLayer mark[data-cm-key]': { color: 'transparent', backgroundColor: 'color-mix(in srgb, var(--cm-color) 30%, transparent)' },
      }}
    >
      {title && <Box component="h2" sx={{ marginTop: 0, fontSize: 20 }}>{title}</Box>}
      {source.kind === 'pdf' ? (
        <Document
          file={`${APP_BASE_PATH}/storage/view/${encodeURIComponent(source.id)}`}
          loading={<Loader variant={LoaderVariant.inElement} />}
          onLoadSuccess={({ numPages }) => setPageCount(numPages)}
        >
          {Array.from({ length: pageCount }, (_, index) => (
            <Page
              key={index}
              pageNumber={index + 1}
              renderAnnotationLayer={false}
              customTextRenderer={pdfTextRenderer}
              onRenderTextLayerSuccess={index === pageCount - 1 ? countPdfMarks : undefined}
            />
          ))}
        </Document>
      ) : (
        <>
          {html === null && <Loader variant={LoaderVariant.inElement} />}
          <div data-cm-html />
          {html === '' && <Box sx={{ color: theme.palette.text.secondary }}>{t_i18n('No content to map: add a description or a content, or choose an attached file.')}</Box>}
        </>
      )}
    </Box>
  );
};

export default ContentMappingDocument;
