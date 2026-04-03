import { Editor, EditorContent, useEditor } from '@tiptap/react';
import { TextSelection, NodeSelection } from '@tiptap/pm/state';
import StarterKit from '@tiptap/starter-kit';
import Link from '@tiptap/extension-link';
import { ImageWithOptions } from './richTextEditor/extensions/ImageWithOptions';
import Underline from '@tiptap/extension-underline';
import Subscript from '@tiptap/extension-subscript';
import Superscript from '@tiptap/extension-superscript';
import TextAlign from '@tiptap/extension-text-align';
import { Highlight } from './richTextEditor/extensions/Highlight';
import { TextStyle } from './richTextEditor/extensions/TextStyle';
import Color from '@tiptap/extension-color';
import { FontFamily } from '@tiptap/extension-text-style/font-family';
import { BackgroundColor } from '@tiptap/extension-text-style/background-color';
import Typography from '@tiptap/extension-typography';
import Mention from '@tiptap/extension-mention';
import { TableRow } from '@tiptap/extension-table';
import { Table } from './richTextEditor/extensions/Table';
import { NestedTableCell } from './richTextEditor/extensions/TableCell';
import { NestedTableHeader } from './richTextEditor/extensions/TableHeader';
import Placeholder from '@tiptap/extension-placeholder';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useTheme } from '@mui/styles';
import Popover from '@mui/material/Popover';
import TextField from '@mui/material/TextField';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import MuiTypography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import { EditOutlined } from '@mui/icons-material';
import { TiptapEditorToolbar } from './richTextEditor/TiptapEditorToolbar';
import { TableContextMenu } from './richTextEditor/TableContextMenu';
import { PageBreak } from './richTextEditor/extensions/PageBreak';
import { TableCellSplit } from './richTextEditor/extensions/TableCellSplit';
import { FontSize } from './richTextEditor/extensions/FontSize';
import { Paragraph } from './richTextEditor/extensions/Paragraph';
import type { Theme } from './Theme';
import { TaskList } from './richTextEditor/extensions/TaskList';
import { TaskItem } from './richTextEditor/extensions/TaskListItem';

import '../static/css/TiptapEditor.css';

export const TIPTAP_EDITOR_SELECTOR = '.tiptap-editor-content.ProseMirror';

export interface RichTextEditorAdapter {
  getData: () => string;
}

export interface RichTextEditorProps {
  id?: string;
  data?: string;
  onChange?: (evt: unknown, editor: RichTextEditorAdapter) => void;
  onReady?: (editor: Editor) => void;
  onBlur?: (evt: unknown, editor: RichTextEditorAdapter) => void;
  onFocus?: (evt: unknown) => void;
  disabled?: boolean;
  disableWatchdog?: boolean;
  placeholder?: string;
}

const createEditorAdapter = (editor: Editor): RichTextEditorAdapter => ({
  getData: () => editor.getHTML(),
});

export const RichTextEditor: React.FC<RichTextEditorProps> = ({
  id,
  data = '',
  onChange,
  onReady,
  onBlur,
  onFocus,
  disabled = false,
  placeholder = '',
}) => {
  const theme = useTheme<Theme>();
  const isDark = theme.palette?.mode === 'dark';
  const initialContentRef = useRef(data);
  const onChangeRef = useRef(onChange);
  const editorRef = useRef<Editor | null>(null);
  onChangeRef.current = onChange;

  const [sourceMode, setSourceMode] = useState(false);
  const [sourceHtml, setSourceHtml] = useState('');

  const formatHtml = (html: string): string => {
    let indent = 0;
    const tab = '  ';
    // Split on tags while keeping the delimiters
    return html
      .replace(/>\s*</g, '><')
      .split(/(<[^>]+>)/)
      .reduce((acc, token) => {
        if (!token) return acc;
        if (/^<\//.test(token)) {
          indent = Math.max(0, indent - 1);
          return `${acc}\n${tab.repeat(indent)}${token}`;
        }
        if (/^<[^/!][^>]*[^/]>$/.test(token) && !/^<(br|hr|img|input|link|meta|area|base|col|embed|param|source|track|wbr)[\s/>]/i.test(token)) {
          const line = `\n${tab.repeat(indent)}${token}`;
          indent += 1;
          return acc + line;
        }
        return `${acc}\n${tab.repeat(indent)}${token}`;
      }, '')
      .trimStart();
  };

  const toggleSourceMode = useCallback(() => {
    if (!editorRef.current) return;
    if (!sourceMode) {
      // switching TO source mode: snapshot current HTML, pretty-printed
      setSourceHtml(formatHtml(editorRef.current.getHTML()));
    } else {
      // switching FROM source mode: apply textarea content back to editor
      editorRef.current.commands.setContent(sourceHtml);
      onChangeRef.current?.(undefined, createEditorAdapter(editorRef.current));
    }
    setSourceMode((prev) => !prev);
  }, [sourceMode, sourceHtml]);

  const [linkPopover, setLinkPopover] = useState<{
    open: boolean;
    position: { top: number; left: number } | null;
    url: string;
    text: string;
    selectionRange: { from: number; to: number } | null; /* stored when opening - used when applying */
  }>({ open: false, position: null, url: '', text: '', selectionRange: null });
  const linkPopoverCallbackRef = useRef<(
    open: boolean,
    position: { top: number; left: number } | null,
    url: string,
    text: string,
    selectionRange: { from: number; to: number } | null,
  ) => void>(() => {});

  const [imagePopover, setImagePopover] = useState<{
    open: boolean;
    position: { top: number; left: number } | null;
    url: string;
    tab: 'url' | 'upload';
    alt: string;
    title: string;
  }>({ open: false, position: null, url: '', tab: 'url', alt: '', title: '' });
  const imageFileInputRef = useRef<HTMLInputElement | null>(null);

  const [imageOptionsPopover, setImageOptionsPopover] = useState<{
    open: boolean;
    position: { top: number; left: number } | null;
    /** Node position of the image being edited; needed to restore selection before updateAttributes */
    imagePos: number | null;
    alt: string;
    title: string;
    caption: string;
    href: string;
  }>({ open: false, position: null, imagePos: null, alt: '', title: '', caption: '', href: '' });

  const [tableContextMenu, setTableContextMenu] = useState<{
    open: boolean;
    position: { top: number; left: number } | null;
  }>({ open: false, position: null });

  /** When an image is selected, show edit icon (do not auto-open options popover). Popover opens only on icon click. */
  const [imageEditButton, setImageEditButton] = useState<{
    pos: number;
    attrs: Record<string, unknown>;
    rect: { top: number; right: number; bottom: number; left: number };
    /** Position relative to editor wrapper so icon scrolls with content */
    relativeTop: number;
    relativeLeft: number;
  } | null>(null);
  const editorWrapRef = useRef<HTMLDivElement | null>(null);
  const editorContentWrapRef = useRef<HTMLDivElement | null>(null);
  const imageEditPosRef = useRef<number | null>(null);
  const imageOptionsPopoverOpenRef = useRef(false);
  imageEditPosRef.current = imageEditButton?.pos ?? null;
  imageOptionsPopoverOpenRef.current = imageOptionsPopover.open;

  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        heading: { levels: [1, 2, 3] },
        paragraph: false,
      }),
      Link.configure({
        autolink: true,
        linkOnPaste: true,
        openOnClick: false,
        HTMLAttributes: {
          style: `color: ${isDark ? '#00b1ff' : '#0066cc'}`,
          target: '_blank',
          rel: 'noopener noreferrer',
        },
      }),
      ImageWithOptions.configure({
        inline: false,
        allowBase64: true,
        resize: {
          enabled: true,
          directions: ['bottom-right', 'bottom-left', 'top-right', 'top-left'],
          minWidth: 8,
          minHeight: 8,
          alwaysPreserveAspectRatio: true,
        },
      }),
      Underline,
      Subscript,
      Superscript,
      TextAlign.configure({ types: ['heading', 'paragraph'] }),
      Paragraph,
      Highlight,
      TextStyle,
      Color,
      BackgroundColor,
      FontFamily,
      FontSize,
      Typography,
      Mention.configure({
        HTMLAttributes: {
          class: 'mention',
        },
        suggestion: {
          char: '@',
          allowSpaces: false,
          items: async () => [],
        },
      }),
      TaskList,
      TaskItem.configure({
        nested: true,
        HTMLAttributes: { class: 'tiptap-task-item' },
      }),
      Table.configure({ resizable: true }),
      TableRow,
      NestedTableHeader,
      NestedTableCell,
      Placeholder.configure({ placeholder }),
      PageBreak,
      TableCellSplit,
    ],
    content: initialContentRef.current,
    editable: !disabled,
    editorProps: {
      attributes: {
        class: 'tiptap-editor-content',
        'aria-label': 'Editing area: main',
        ...(id ? { 'data-editor-id': id } : {}),
      },
      handlePaste: (_view, event) => {
        const items = event.clipboardData?.items;
        if (!items) return false;
        for (const item of Array.from(items)) {
          if (item.type.startsWith('image/')) {
            const file = item.getAsFile();
            if (file) {
              const reader = new FileReader();
              reader.onload = () => {
                const result = reader.result as string;
                if (result) {
                  editorRef.current?.chain().focus().setImage({ src: result }).run();
                }
              };
              reader.readAsDataURL(file);
              return true;
            }
          }
        }
        return false;
      },
      handleClick: (view, pos, event) => {
        if (disabled) return false;
        const target = event.target as HTMLElement;
        const link = target.closest('a');
        if (link) {
          // Linked images are edited through image options, not link popover.
          const clickedImage = target.closest('img');
          if (clickedImage && link.contains(clickedImage)) {
            event.preventDefault();
            return true;
          }

          // Text links: keep click-to-edit behavior (no navigation).
          event.preventDefault();
          const href = link.getAttribute('href') ?? '';
          const linkStart = view.posAtDOM(link, 0);
          const linkEnd = view.posAtDOM(link, 1);
          editorRef.current?.chain().focus().setTextSelection({ from: linkStart, to: linkEnd }).run();
          const coords = view.coordsAtPos(pos);
          linkPopoverCallbackRef.current(true, { top: coords.bottom + 4, left: coords.left }, href, link.textContent ?? '', {
            from: linkStart,
            to: linkEnd,
          });
          return true;
        }
        return false;
      },
      handleDrop: (_view, event) => {
        const files = event.dataTransfer?.files;
        if (!files?.length) return false;
        const file = files[0];
        if (file.type.startsWith('image/')) {
          const reader = new FileReader();
          reader.onload = () => {
            const result = reader.result as string;
            if (result) {
              editorRef.current?.chain().focus().setImage({ src: result }).run();
            }
          };
          reader.readAsDataURL(file);
          event.preventDefault();
          return true;
        }
        return false;
      },
    },
  } as Parameters<typeof useEditor>[0]);

  useEffect(() => {
    editorRef.current = editor ?? null;
  }, [editor]);

  linkPopoverCallbackRef.current = (
    open: boolean,
    position: { top: number; left: number } | null,
    url: string,
    text: string,
    selectionRange: { from: number; to: number } | null,
  ) => {
    setLinkPopover({ open, position, url, text, selectionRange });
  };

  const openLinkPopoverFromToolbar = useCallback(() => {
    if (!editor) return;
    const { from, to } = editor.state.selection;
    const coords = editor.view.coordsAtPos(from);
    const hasSelection = from !== to;
    setLinkPopover({
      open: true,
      position: { top: coords.bottom + 4, left: coords.left },
      url: editor.getAttributes('link').href ?? '',
      text: hasSelection ? editor.state.doc.textBetween(from, to, ' ') : '',
      selectionRange: hasSelection ? { from, to } : null,
    });
  }, [editor]);

  const closeLinkPopover = useCallback(() => {
    setLinkPopover((p) => ({ ...p, open: false }));
  }, []);

  const moveCursorAfterLink = useCallback((pos: number) => {
    if (!editor) return;
    const { state, view } = editor;
    const tr = state.tr
      .setSelection(TextSelection.create(state.doc, pos))
      .setStoredMarks([]);
    view.dispatch(tr);
  }, [editor]);

  const applyLink = useCallback(() => {
    if (!editor) return;
    const url = linkPopover.url.trim();
    const storedRange = linkPopover.selectionRange;
    const linkText = linkPopover.text;

    if (url === '') {
      if (storedRange) {
        editor.chain().focus().setTextSelection(storedRange).unsetLink().run();
        moveCursorAfterLink(storedRange.to);
      } else if (editor.isActive('link')) {
        editor.chain().focus().extendMarkRange('link').unsetLink().run();
      }
    } else if (storedRange) {
      const currentText = editor.state.doc.textBetween(storedRange.from, storedRange.to, ' ');
      const nextText = linkText !== '' ? linkText : currentText;
      editor
        .chain()
        .focus()
        .insertContentAt({ from: storedRange.from, to: storedRange.to }, nextText)
        .setTextSelection({ from: storedRange.from, to: storedRange.from + nextText.length })
        .setLink({ href: url })
        .run();
      moveCursorAfterLink(storedRange.from + nextText.length);
    } else {
      const text = linkText.trim() || url;
      const escapedUrl = url
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      const escapedText = text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
      editor
        .chain()
        .focus()
        .insertContent(`<a href="${escapedUrl}">${escapedText}</a>`)
        .run();
      moveCursorAfterLink(editor.state.selection.to);
    }
    closeLinkPopover();
  }, [editor, linkPopover.url, linkPopover.text, linkPopover.selectionRange, closeLinkPopover, moveCursorAfterLink]);

  const removeLink = useCallback(() => {
    if (!editor) return;
    const storedRange = linkPopover.selectionRange;
    if (storedRange) {
      editor.chain().focus().setTextSelection(storedRange).unsetLink().run();
    } else {
      editor.chain().focus().extendMarkRange('link').unsetLink().run();
    }
    closeLinkPopover();
  }, [editor, linkPopover.selectionRange, closeLinkPopover]);

  const openImagePopoverFromToolbar = useCallback(() => {
    if (!editor) return;
    const { from } = editor.state.selection;
    const coords = editor.view.coordsAtPos(from);
    setImagePopover({
      open: true,
      position: { top: coords.bottom + 4, left: coords.left },
      url: '',
      tab: 'url',
      alt: '',
      title: '',
    });
  }, [editor]);

  const closeImagePopover = useCallback(() => {
    setImagePopover((p) => ({ ...p, open: false }));
    if (imageFileInputRef.current) {
      imageFileInputRef.current.value = '';
    }
  }, []);

  const applyImageFromUrl = useCallback(() => {
    if (!editor) return;
    const url = imagePopover.url.trim();
    if (url) {
      editor.chain().focus().setImage({
        src: url,
        alt: imagePopover.alt || undefined,
        title: imagePopover.title || undefined,
      }).run();
    }
    closeImagePopover();
  }, [editor, imagePopover.url, imagePopover.alt, imagePopover.title, closeImagePopover]);

  const handleImageFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file || !file.type.startsWith('image/') || !editor) return;
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result as string;
        if (result) {
          editor.chain().focus().setImage({
            src: result,
            alt: imagePopover.alt || undefined,
            title: imagePopover.title || undefined,
          }).run();
        }
        closeImagePopover();
        if (imageFileInputRef.current) {
          imageFileInputRef.current.value = '';
        }
      };
      reader.readAsDataURL(file);
    },
    [editor, closeImagePopover, imagePopover.alt, imagePopover.title],
  );

  const closeImageOptionsPopover = useCallback(() => {
    setImageOptionsPopover((p) => ({ ...p, open: false }));
  }, []);

  const applyImageOptions = useCallback(() => {
    if (!editor) return;
    const pos = imageOptionsPopover.imagePos;
    const attrs = {
      alt: imageOptionsPopover.alt || null,
      title: imageOptionsPopover.title || null,
      caption: imageOptionsPopover.caption || null,
      href: imageOptionsPopover.href?.trim() || null,
    };
    if (pos == null) {
      closeImageOptionsPopover();
      return;
    }
    // Apply synchronously before closing popover, so mode switches/onBlur
    // don't overwrite content with stale HTML.
    const { state, view } = editor;
    const node = state.doc.nodeAt(pos);
    if (!node || node.type.name !== 'image') return;
    const tr = state.tr
      .setSelection(NodeSelection.create(state.doc, pos))
      .setNodeMarkup(pos, undefined, { ...node.attrs, ...attrs });
    view.dispatch(tr);
    // Force immediate upstream sync to avoid losing attrs on fast mode toggles
    // where blur/update listeners can race with unmount.
    if (onChangeRef.current) {
      onChangeRef.current(null, createEditorAdapter(editor));
    }
    closeImageOptionsPopover();
  }, [editor, imageOptionsPopover, closeImageOptionsPopover]);

  /** Get the visual element for the image (img or figure), not the resize wrapper. */
  const getImageVisualElement = useCallback((dom: Node | null): HTMLElement | null => {
    if (!(dom instanceof HTMLElement)) return null;
    const figure = dom.classList?.contains('image-figure') ? dom : dom.querySelector('.image-figure');
    const img = dom.tagName === 'IMG' ? dom : dom.querySelector('img');
    return (figure ?? img ?? dom) as HTMLElement;
  }, []);

  // Compute icon position relative to the inner content wrapper so the icon scrolls with the editor content.
  // Icon sits slightly inside the image (bottom-right), left of the resize handle.
  const computeRelativePos = useCallback(
    (imageRect: DOMRect, contentWrap: HTMLDivElement) => {
      const wrapRect = contentWrap.getBoundingClientRect();
      const iconWidth = 28;
      const gapFromHandle = 14;
      return {
        relativeTop: imageRect.bottom - wrapRect.top - 24,
        relativeLeft: imageRect.right - wrapRect.left - iconWidth - gapFromHandle,
      };
    },
    [],
  );

  const updateImageEditButtonRect = useCallback(() => {
    const pos = imageEditPosRef.current;
    if (!editor || pos == null || !editorContentWrapRef.current) return;
    const dom = editor.view.nodeDOM(pos);
    const el = getImageVisualElement(dom);
    const contentWrap = editorContentWrapRef.current;
    if (!el || !contentWrap) {
      setImageEditButton(null);
      return;
    }
    const rect = el.getBoundingClientRect();
    const { relativeTop, relativeLeft } = computeRelativePos(rect, contentWrap);
    setImageEditButton((prev) =>
      prev
        ? {
            ...prev,
            rect: { top: rect.top, right: rect.right, bottom: rect.bottom, left: rect.left },
            relativeTop,
            relativeLeft,
          }
        : null,
    );
  }, [editor, getImageVisualElement, computeRelativePos]);

  /** Show edit icon when mouse is over an image (hover), not on selection. */
  useEffect(() => {
    if (!editor || !editorContentWrapRef.current || disabled) return;
    const view = editor.view;
    const contentWrap = editorContentWrapRef.current;

    const getImageUnderCoords = (clientX: number, clientY: number) => {
      const result = view.posAtCoords({ left: clientX, top: clientY });
      if (!result) return null;
      const { pos } = result;
      const { doc } = editor.state;
      const $pos = doc.resolve(pos);
      const nodeAfter = $pos.nodeAfter;
      const nodeBefore = $pos.nodeBefore;
      if (nodeAfter?.type.name === 'image') {
        return { node: nodeAfter, pos };
      }
      if (nodeBefore?.type.name === 'image') {
        return { node: nodeBefore, pos: pos - nodeBefore.nodeSize };
      }
      return null;
    };

    const onMouseMove = (e: MouseEvent) => {
      const hit = getImageUnderCoords(e.clientX, e.clientY);
      if (!hit) {
        setImageEditButton(null);
        return;
      }
      const dom = view.nodeDOM(hit.pos);
      const el = getImageVisualElement(dom);
      const rect = el?.getBoundingClientRect();
      if (!rect || !contentWrap) {
        setImageEditButton(null);
        return;
      }
      const { relativeTop, relativeLeft } = computeRelativePos(rect, contentWrap);
      setImageEditButton({
        pos: hit.pos,
        attrs: hit.node.attrs,
        rect: { top: rect.top, right: rect.right, bottom: rect.bottom, left: rect.left },
        relativeTop,
        relativeLeft,
      });
    };

    const onMouseLeave = () => {
      if (imageOptionsPopoverOpenRef.current) return;
      setImageEditButton(null);
    };

    const el = contentWrap;
    el.addEventListener('mousemove', onMouseMove);
    el.addEventListener('mouseleave', onMouseLeave);
    return () => {
      el.removeEventListener('mousemove', onMouseMove);
      el.removeEventListener('mouseleave', onMouseLeave);
    };
  }, [editor, disabled, getImageVisualElement, computeRelativePos]);

  useEffect(() => {
    if (!imageEditButton || !editorWrapRef.current) return;
    const scrollEl = editorWrapRef.current;
    const onScroll = () => updateImageEditButtonRect();
    scrollEl.addEventListener('scroll', onScroll, true);
    return () => scrollEl.removeEventListener('scroll', onScroll, true);
  }, [imageEditButton, updateImageEditButtonRect]);

  const openImageOptionsFromEditIcon = useCallback(() => {
    if (!imageEditButton) return;
    setImageOptionsPopover({
      open: true,
      position: { top: imageEditButton.rect.bottom + 4, left: imageEditButton.rect.left },
      imagePos: imageEditButton.pos,
      alt: String(imageEditButton.attrs.alt ?? ''),
      title: String(imageEditButton.attrs.title ?? ''),
      caption: String(imageEditButton.attrs.caption ?? ''),
      href: String(imageEditButton.attrs.href ?? ''),
    });
  }, [imageEditButton]);

  const handleTableContextMenu = useCallback(
    (e: React.MouseEvent) => {
      if (!editor || disabled) return;
      if (editor.isActive('table')) {
        e.preventDefault();
        setTableContextMenu({
          open: true,
          position: { top: e.clientY, left: e.clientX },
        });
      }
    },
    [editor, disabled],
  );

  const closeTableContextMenu = useCallback(() => {
    setTableContextMenu({ open: false, position: null });
    // Preserve scroll position: closing the menu can trigger ProseMirror
    // scrollIntoView which jumps the editor to the cursor.
    const scrollEl = editorWrapRef.current;
    if (scrollEl) {
      const { scrollTop, scrollLeft } = scrollEl;
      requestAnimationFrame(() => {
        scrollEl.scrollTop = scrollTop;
        scrollEl.scrollLeft = scrollLeft;
      });
    }
  }, []);

  useEffect(() => {
    if (editor && onReady) {
      onReady(editor);
    }
  }, [editor, onReady]);

  useEffect(() => {
    if (!editor) return;
    if (data !== undefined && data !== editor.getHTML()) {
      editor.commands.setContent(data || '<p></p>', { emitUpdate: false });
    }
  }, [data, editor]);

  useEffect(() => {
    if (editor) editor.setEditable(!disabled);
  }, [editor, disabled]);

  useEffect(() => {
    if (!editor) return;
    const handler = () => {
      if (onChangeRef.current) {
        onChangeRef.current(null, createEditorAdapter(editor));
      }
    };
    editor.on('update', handler);
    return () => {
      editor.off('update', handler);
    };
  }, [editor]);

  useEffect(() => {
    if (!editor || !onBlur) return;
    const handler = ({ event }: { event: FocusEvent }) => onBlur(event, createEditorAdapter(editor));
    editor.on('blur', handler);
    return () => {
      editor.off('blur', handler);
    };
  }, [editor, onBlur]);

  useEffect(() => {
    if (!editor || !onFocus) return;
    const handler = ({ event }: { event: FocusEvent }) => onFocus(event);
    editor.on('focus', handler);
    return () => {
      editor.off('focus', handler);
    };
  }, [editor, onFocus]);

  if (!editor) {
    return null;
  }

  return (
    <div
      className="rich-text-editor-wrapper"
      style={{ height: '100%', display: 'flex', flexDirection: 'column' }}
    >
      <TiptapEditorToolbar
        editor={editor}
        disabled={disabled}
        onOpenLinkPopover={openLinkPopoverFromToolbar}
        onOpenImagePopover={openImagePopoverFromToolbar}
        isSourceMode={sourceMode}
        onToggleSourceMode={toggleSourceMode}
      />
      <div
        ref={editorWrapRef}
        style={{ flex: 1, minHeight: 0, overflow: 'auto' }}
      >
        {sourceMode ? (
          <textarea
            value={sourceHtml}
            onChange={(e) => setSourceHtml(e.target.value)}
            style={{
              width: '100%',
              height: '100%',
              minHeight: 200,
              padding: 12,
              fontFamily: 'monospace',
              fontSize: 13,
              border: 'none',
              outline: 'none',
              resize: 'none',
              background: 'transparent',
              color: 'inherit',
              boxSizing: 'border-box',
            }}
            spellCheck={false}
          />
        ) : (
          <div
            ref={editorContentWrapRef}
            onContextMenu={handleTableContextMenu}
            style={{ position: 'relative', minHeight: '100%' }}
          >
            <EditorContent editor={editor} />
            {!disabled && imageEditButton && !imageOptionsPopover.open && (
              <IconButton
                size="small"
                aria-label="Edit image options"
                onClick={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  openImageOptionsFromEditIcon();
                }}
                sx={{
                  position: 'absolute',
                  top: imageEditButton.relativeTop,
                  left: imageEditButton.relativeLeft,
                  width: 28,
                  height: 28,
                  backgroundColor: 'background.paper',
                  border: '1px solid',
                  borderColor: 'divider',
                  boxShadow: 1,
                  '&:hover': { backgroundColor: 'action.hover' },
                  zIndex: 10,
                }}
              >
                <EditOutlined sx={{ fontSize: 16 }} />
              </IconButton>
            )}
          </div>
        )}
      </div>
      <Popover
        open={linkPopover.open}
        onClose={closeLinkPopover}
        anchorReference="anchorPosition"
        anchorPosition={
          linkPopover.position
            ? { top: linkPopover.position.top, left: linkPopover.position.left }
            : undefined
        }
        transformOrigin={{ vertical: 'top', horizontal: 'left' }}
        PaperProps={{
          sx: { mt: 0.5 },
          onKeyDownCapture: (e: React.KeyboardEvent) => {
            if (e.key === 'Enter' || e.key === 'Escape') {
              e.preventDefault();
              e.stopPropagation();
              if (e.key === 'Enter') applyLink();
              else closeLinkPopover();
            }
          },
        }}
      >
        <Stack sx={{ p: 2, minWidth: 280 }} spacing={1}>
          <TextField
            size="small"
            label="Text"
            placeholder="Link text"
            value={linkPopover.text}
            onChange={(e) => setLinkPopover((p) => ({ ...p, text: e.target.value }))}
            fullWidth
          />
          <TextField
            size="small"
            label="URL"
            placeholder="https://"
            value={linkPopover.url}
            onChange={(e) => setLinkPopover((p) => ({ ...p, url: e.target.value }))}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                e.stopPropagation();
                applyLink();
              }
              if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                closeLinkPopover();
              }
            }}
            autoFocus
            fullWidth
          />
          <Stack direction="row" spacing={1} justifyContent="flex-end">
            {editor.isActive('link') && (
              <Button size="small" onClick={removeLink} color="error">
                Remove link
              </Button>
            )}
            <Button size="small" variant="contained" onClick={applyLink}>
              Apply
            </Button>
          </Stack>
        </Stack>
      </Popover>
      <Popover
        open={imagePopover.open}
        onClose={closeImagePopover}
        anchorReference="anchorPosition"
        anchorPosition={
          imagePopover.position
            ? { top: imagePopover.position.top, left: imagePopover.position.left }
            : undefined
        }
        transformOrigin={{ vertical: 'top', horizontal: 'left' }}
        PaperProps={{
          sx: { mt: 0.5 },
          onKeyDownCapture: (e: React.KeyboardEvent) => {
            if (e.key === 'Escape') {
              e.preventDefault();
              e.stopPropagation();
              closeImagePopover();
            }
          },
        }}
      >
        <Stack sx={{ p: 0, minWidth: 320 }} spacing={0}>
          <Tabs
            value={imagePopover.tab}
            onChange={(_e, v: 'url' | 'upload') => setImagePopover((p) => ({ ...p, tab: v }))}
            variant="fullWidth"
            sx={{ borderBottom: 1, borderColor: 'divider', minHeight: 40 }}
          >
            <Tab label="By URL" value="url" />
            <Tab label="Upload" value="upload" />
          </Tabs>
          <Box sx={{ p: 2 }}>
            {imagePopover.tab === 'url' && (
              <Stack spacing={1.5}>
                <TextField
                  size="small"
                  label="Image URL"
                  placeholder="https://…"
                  value={imagePopover.url}
                  onChange={(e) => setImagePopover((p) => ({ ...p, url: e.target.value }))}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      applyImageFromUrl();
                    }
                    if (e.key === 'Escape') closeImagePopover();
                  }}
                  autoFocus
                  fullWidth
                />
                <TextField
                  size="small"
                  label="Alt text"
                  placeholder="Optional description"
                  value={imagePopover.alt}
                  onChange={(e) => setImagePopover((p) => ({ ...p, alt: e.target.value }))}
                  fullWidth
                />
                <TextField
                  size="small"
                  label="Tooltip"
                  placeholder="Optional tooltip on hover"
                  value={imagePopover.title}
                  onChange={(e) => setImagePopover((p) => ({ ...p, title: e.target.value }))}
                  fullWidth
                />
                <Stack direction="row" spacing={1} justifyContent="flex-end">
                  <Button size="small" onClick={closeImagePopover}>
                    Cancel
                  </Button>
                  <Button size="small" variant="contained" onClick={applyImageFromUrl} disabled={!imagePopover.url.trim()}>
                    Insert
                  </Button>
                </Stack>
              </Stack>
            )}
            {imagePopover.tab === 'upload' && (
              <Stack spacing={1.5}>
                <TextField
                  size="small"
                  label="Alt text"
                  placeholder="Optional description"
                  value={imagePopover.alt}
                  onChange={(e) => setImagePopover((p) => ({ ...p, alt: e.target.value }))}
                  fullWidth
                />
                <TextField
                  size="small"
                  label="Tooltip"
                  placeholder="Optional tooltip on hover"
                  value={imagePopover.title}
                  onChange={(e) => setImagePopover((p) => ({ ...p, title: e.target.value }))}
                  fullWidth
                />
                <Button
                  size="small"
                  variant="outlined"
                  component="label"
                  fullWidth
                  sx={{ py: 1.5 }}
                >
                  Choose image…
                  <input
                    ref={imageFileInputRef}
                    type="file"
                    accept="image/*"
                    onChange={handleImageFileSelect}
                    hidden
                  />
                </Button>
                <MuiTypography variant="caption" color="text.secondary" sx={{ textAlign: 'center' }}>
                  Image will be embedded in the content.
                </MuiTypography>
              </Stack>
            )}
          </Box>
        </Stack>
      </Popover>
      <Popover
        open={imageOptionsPopover.open}
        onClose={closeImageOptionsPopover}
        anchorReference="anchorPosition"
        anchorPosition={
          imageOptionsPopover.position
            ? { top: imageOptionsPopover.position.top, left: imageOptionsPopover.position.left }
            : undefined
        }
        transformOrigin={{ vertical: 'top', horizontal: 'left' }}
        PaperProps={{
          sx: { mt: 0.5 },
          onKeyDownCapture: (e: React.KeyboardEvent) => {
            if (e.key === 'Enter' || e.key === 'Escape') {
              e.preventDefault();
              e.stopPropagation();
              if (e.key === 'Enter') applyImageOptions();
              else closeImageOptionsPopover();
            }
          },
        }}
      >
        <Stack sx={{ p: 2, minWidth: 320 }} spacing={1.5}>
          <MuiTypography variant="subtitle2" color="text.secondary">
            Image options
          </MuiTypography>
          <TextField
            size="small"
            label="Alt text"
            placeholder="Description for accessibility"
            value={imageOptionsPopover.alt}
            onChange={(e) => setImageOptionsPopover((p) => ({ ...p, alt: e.target.value }))}
            fullWidth
          />
          <TextField
            size="small"
            label="Tooltip"
            placeholder="Tooltip on hover"
            value={imageOptionsPopover.title}
            onChange={(e) => setImageOptionsPopover((p) => ({ ...p, title: e.target.value }))}
            fullWidth
          />
          <TextField
            size="small"
            label="Caption"
            placeholder="Caption below image"
            value={imageOptionsPopover.caption}
            onChange={(e) => setImageOptionsPopover((p) => ({ ...p, caption: e.target.value }))}
            fullWidth
          />
          <TextField
            size="small"
            label="Link"
            placeholder="https://…"
            value={imageOptionsPopover.href}
            onChange={(e) => setImageOptionsPopover((p) => ({ ...p, href: e.target.value }))}
            fullWidth
          />
          <Stack direction="row" spacing={1} justifyContent="flex-end">
            <Button size="small" onClick={closeImageOptionsPopover}>
              Cancel
            </Button>
            <Button size="small" variant="contained" onClick={applyImageOptions}>
              Apply
            </Button>
          </Stack>
        </Stack>
      </Popover>
      <TableContextMenu
        editor={editor}
        open={tableContextMenu.open}
        position={tableContextMenu.position}
        onClose={closeTableContextMenu}
      />
    </div>
  );
};

export default RichTextEditor;
