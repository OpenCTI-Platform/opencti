import type { Editor } from '@tiptap/react';
import React from 'react';
import {
  FormatBold,
  FormatItalic,
  FormatUnderlined,
  FormatStrikethrough,
  FormatListBulleted,
  FormatListNumbered,
  FormatQuote,
  Code,
  DataObject,
  Html,
  Link as LinkIcon,
  Image as ImageIcon,
  HorizontalRule,
  TableChart,
  ViewAgenda,
  FormatAlignLeft,
  FormatAlignCenter,
  FormatAlignRight,
  FormatAlignJustify,
  Highlight,
  Subscript as SubscriptIcon,
  Superscript as SuperscriptIcon,
  Undo,
  Redo,
  ChecklistRtl,
  FormatColorText,
  FormatPaint,
  FormatSize,
  FontDownload,
  ArrowDropDown,
  FormatIndentIncrease,
  FormatIndentDecrease,
  MoreVert,
} from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import IconButton from '@mui/material/IconButton';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import Select from '@mui/material/Select';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Popover from '@mui/material/Popover';
import { SketchPicker } from 'react-color';
import { TableGridPicker } from './TableGridPicker';

const HEADING_OPTIONS = [
  { value: 'paragraph', label: 'Paragraph', level: null },
  { value: 'h1', label: 'Heading 1', level: 1 },
  { value: 'h2', label: 'Heading 2', level: 2 },
  { value: 'h3', label: 'Heading 3', level: 3 },
] as const;

const FONT_FAMILY_OPTIONS = [
  { value: '', label: 'Default' },
  { value: 'Arial', label: 'Arial' },
  { value: 'Courier New', label: 'Courier New' },
  { value: 'Georgia', label: 'Georgia' },
  { value: 'Helvetica', label: 'Helvetica' },
  { value: 'Lucida Sans Unicode', label: 'Lucida Sans Unicode' },
  { value: 'Times New Roman', label: 'Times New Roman' },
  { value: 'Trebuchet MS', label: 'Trebuchet MS' },
  { value: 'Verdana', label: 'Verdana' },
] as const;

const ALIGN_OPTIONS = [
  { value: 'left', label: 'Align Left', icon: FormatAlignLeft },
  { value: 'center', label: 'Align Center', icon: FormatAlignCenter },
  { value: 'right', label: 'Align Right', icon: FormatAlignRight },
  { value: 'justify', label: 'Justify', icon: FormatAlignJustify },
] as const;

const FONT_SIZE_OPTIONS = [
  { value: '', label: 'Default' },
  { value: '10px', label: 'Tiny' },
  { value: '12px', label: 'Small' },
  { value: '14px', label: 'Normal' },
  { value: '18px', label: 'Big' },
  { value: '24px', label: 'Huge' },
] as const;

interface TiptapEditorToolbarProps {
  editor: Editor;
  disabled?: boolean;
  onOpenLinkPopover?: () => void;
  onOpenImagePopover?: () => void;
  isSourceMode?: boolean;
  onToggleSourceMode?: () => void;
}

export const TiptapEditorToolbar: React.FC<TiptapEditorToolbarProps> = ({
  editor,
  disabled = false,
  onOpenLinkPopover,
  onOpenImagePopover,
  isSourceMode = false,
  onToggleSourceMode,
}) => {
  const [, forceUpdate] = React.useReducer((x) => x + 1, 0);
  React.useEffect(() => {
    if (!editor) return;
    editor.on('selectionUpdate', forceUpdate);
    editor.on('transaction', forceUpdate);
    return () => {
      editor.off('selectionUpdate', forceUpdate);
      editor.off('transaction', forceUpdate);
    };
  }, [editor]);

  const [textColorAnchor, setTextColorAnchor] = React.useState<HTMLElement | null>(null);
  const [bgColorAnchor, setBgColorAnchor] = React.useState<HTMLElement | null>(null);
  const [fontFamilyAnchor, setFontFamilyAnchor] = React.useState<HTMLElement | null>(null);
  const [fontSizeAnchor, setFontSizeAnchor] = React.useState<HTMLElement | null>(null);
  const [alignAnchor, setAlignAnchor] = React.useState<HTMLElement | null>(null);
  const [tableGridAnchor, setTableGridAnchor] = React.useState<HTMLElement | null>(null);
  const [moreAnchor, setMoreAnchor] = React.useState<HTMLElement | null>(null);

  const currentHeading
    = editor.isActive('heading', { level: 1 })
      ? 'h1'
      : editor.isActive('heading', { level: 2 })
        ? 'h2'
        : editor.isActive('heading', { level: 3 })
          ? 'h3'
          : 'paragraph';

  const currentFontFamily = editor.getAttributes('textStyle').fontFamily ?? '';
  const currentFontSize = editor.getAttributes('textStyle').fontSize ?? '';
  const currentColor = editor.getAttributes('textStyle').color ?? '';
  const currentAlign = editor.isActive({ textAlign: 'center' })
    ? 'center'
    : editor.isActive({ textAlign: 'right' })
      ? 'right'
      : editor.isActive({ textAlign: 'justify' })
        ? 'justify'
        : 'left';
  const currentBgColor = editor.getAttributes('textStyle').backgroundColor ?? '';

  const insertPageBreak = () => {
    editor.chain().focus().setPageBreak().run();
  };

  const indent = () => editor.chain().focus().indent().run();
  const outdent = () => editor.chain().focus().outdent().run();

  // --- Overflow menu ---
  const toolbarRef = React.useRef<HTMLDivElement>(null);
  const [hiddenItems, setHiddenItems] = React.useState<Set<string>>(new Set());
  const cachedWidthsRef = React.useRef<Record<string, number>>({});

  const hasSourceMode = Boolean(onToggleSourceMode);

  const itemGroups = React.useMemo(
    () => [
      ['heading-select'],
      ['font-family', 'font-size', 'bold', 'italic', 'underline', 'strike'],
      ['text-color', 'bg-color', 'highlight'],
      ['align', 'bullet-list', 'ordered-list', 'indent', 'outdent', 'task-list'],
      ['link', 'image', 'blockquote', 'code', 'code-block', 'subscript', 'superscript'],
      ['table', 'page-break', 'hr'],
      ...(hasSourceMode ? [['source']] : []),
      ['undo', 'redo'],
    ],
    [hasSourceMode],
  );

  const itemIds = React.useMemo(
    () => itemGroups.flat(),
    [itemGroups],
  );

  React.useEffect(() => {
    const container = toolbarRef.current;
    if (!container) return;

    // Phase 1: cache natural widths of all items (all visible on first render)
    itemIds.forEach((id) => {
      const el = container.querySelector<HTMLElement>(`[data-toolbar-item="${id}"]`);
      if (el && el.offsetWidth > 0) {
        cachedWidthsRef.current[id] = el.offsetWidth;
      }
    });

    // Build lookup: item id → group index (gap is between groups, not between items)
    const groupOf: Record<string, number> = {};
    itemGroups.forEach((group, gi) => {
      group.forEach((id) => {
        groupOf[id] = gi;
      });
    });

    const INTER_GROUP_GAP = 4; // gap: 0.5 = 4px between group Boxes

    const measure = () => {
      const containerWidth = container.clientWidth;

      // Total natural width: one gap per group transition, not per item
      let totalNatural = 0;
      let lastGroup = -1;
      for (const id of itemIds) {
        const w = cachedWidthsRef.current[id] ?? 0;
        if (w === 0) continue;
        const gi = groupOf[id];
        if (lastGroup !== -1 && gi !== lastGroup) totalNatural += INTER_GROUP_GAP;
        totalNatural += w;
        lastGroup = gi;
      }

      if (totalNatural <= containerWidth) {
        setMoreAnchor(null);
        setHiddenItems((prev) => (prev.size === 0 ? prev : new Set()));
        return;
      }

      const MORE_BTN_WIDTH = 36;
      const available = containerWidth - MORE_BTN_WIDTH;
      let used = 0;
      const newHidden = new Set<string>();
      let overflowing = false;
      let lastVisibleGroup = -1;

      for (const id of itemIds) {
        const w = cachedWidthsRef.current[id] ?? 0;
        const gi = groupOf[id];
        const gapCost = (lastVisibleGroup !== -1 && gi !== lastVisibleGroup) ? INTER_GROUP_GAP : 0;

        if (!overflowing && used + gapCost + w <= available) {
          used += gapCost + w;
          lastVisibleGroup = gi;
        } else {
          overflowing = true;
          newHidden.add(id);
        }
      }

      setHiddenItems((prev) => {
        if (prev.size === newHidden.size && Array.from(prev).every((id) => newHidden.has(id))) return prev;
        return newHidden;
      });
    };

    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(container);
    return () => ro.disconnect();
  }, [itemIds, itemGroups]);

  return (
    <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
      <Box
        ref={toolbarRef}
        onMouseDown={(e) => e.preventDefault()}
        sx={{
          display: 'flex',
          flexWrap: 'nowrap',
          alignItems: 'center',
          gap: 0.5,
          p: 0.5,
          minHeight: 40,
          overflow: 'hidden',
        }}
      >
        {/* heading */}
        {!hiddenItems.has('heading-select') && (
          <Box
            data-toolbar-item="heading-select"
            sx={{ display: 'inline-flex', alignItems: 'center' }}
          >
            <Select
              size="small"
              disabled={disabled}
              value={currentHeading}
              onChange={(e) => {
                const opt = HEADING_OPTIONS.find((o) => o.value === e.target.value);
                if (!opt) return;
                if (opt.level === null) {
                  editor.chain().focus().setParagraph().run();
                } else {
                  editor.chain().focus().toggleHeading({ level: opt.level }).run();
                }
              }}
              displayEmpty
              sx={{ minWidth: 130, height: 32 }}
            >
              {HEADING_OPTIONS.map((o) => (
                <MenuItem key={o.value} value={o.value}>
                  {o.label}
                </MenuItem>
              ))}
            </Select>
          </Box>
        )}
        {/* font-format: font family, font size, bold, italic, underline, strike */}
        {!['font-family', 'font-size', 'bold', 'italic', 'underline', 'strike'].every((id) => hiddenItems.has(id)) && (
          <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
            <ToggleButtonGroup size="small" disabled={disabled}>
              {!hiddenItems.has('font-family') && (
                <Tooltip title="Font Family">
                  <ToggleButton
                    value="fontFamily"
                    data-toolbar-item="font-family"
                    selected={Boolean(fontFamilyAnchor)}
                    onClick={(e) => setFontFamilyAnchor(fontFamilyAnchor ? null : e.currentTarget)}
                    sx={{ pr: 0.25 }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <FontDownload fontSize="small" />
                      <ArrowDropDown sx={{ fontSize: 18 }} />
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('font-size') && (
                <Tooltip title="Font Size">
                  <ToggleButton
                    value="fontSize"
                    data-toolbar-item="font-size"
                    selected={Boolean(fontSizeAnchor)}
                    onClick={(e) => setFontSizeAnchor(fontSizeAnchor ? null : e.currentTarget)}
                    sx={{ pr: 0.25 }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <FormatSize fontSize="small" />
                      <ArrowDropDown sx={{ fontSize: 18 }} />
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('bold') && (
                <Tooltip title="Bold">
                  <ToggleButton
                    value="bold"
                    data-toolbar-item="bold"
                    selected={editor.isActive('bold')}
                    onClick={() => editor.chain().focus().toggleBold().run()}
                  >
                    <FormatBold fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('italic') && (
                <Tooltip title="Italic">
                  <ToggleButton
                    value="italic"
                    data-toolbar-item="italic"
                    selected={editor.isActive('italic')}
                    onClick={() => editor.chain().focus().toggleItalic().run()}
                  >
                    <FormatItalic fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('underline') && (
                <Tooltip title="Underline">
                  <ToggleButton
                    value="underline"
                    data-toolbar-item="underline"
                    selected={editor.isActive('underline')}
                    onClick={() => editor.chain().focus().toggleUnderline().run()}
                  >
                    <FormatUnderlined fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('strike') && (
                <Tooltip title="Strikethrough">
                  <ToggleButton
                    value="strike"
                    data-toolbar-item="strike"
                    selected={editor.isActive('strike')}
                    onClick={() => editor.chain().focus().toggleStrike().run()}
                  >
                    <FormatStrikethrough fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          </Box>
        )}
        {/* Font family/size menus — always rendered (portals, don't affect layout) */}
        <Menu
          anchorEl={fontFamilyAnchor}
          open={Boolean(fontFamilyAnchor)}
          onClose={() => setFontFamilyAnchor(null)}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        >
          {FONT_FAMILY_OPTIONS.map((o) => (
            <MenuItem
              key={o.value || 'default'}
              selected={currentFontFamily === o.value}
              onClick={() => {
                if (o.value) editor.chain().focus().setFontFamily(o.value).run();
                else editor.chain().focus().unsetFontFamily().run();
                setFontFamilyAnchor(null);
              }}
              sx={{ fontFamily: o.value || 'inherit' }}
            >
              {o.label}
            </MenuItem>
          ))}
        </Menu>
        <Menu
          anchorEl={fontSizeAnchor}
          open={Boolean(fontSizeAnchor)}
          onClose={() => setFontSizeAnchor(null)}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        >
          {FONT_SIZE_OPTIONS.map((o) => (
            <MenuItem
              key={o.value || 'default'}
              selected={currentFontSize === o.value}
              onClick={() => {
                if (o.value) editor.chain().focus().setFontSize(o.value).run();
                else editor.chain().focus().unsetFontSize().run();
                setFontSizeAnchor(null);
              }}
            >
              {o.label}
            </MenuItem>
          ))}
        </Menu>
        {/* color: text color, background color, highlight */}
        {!['text-color', 'bg-color', 'highlight'].every((id) => hiddenItems.has(id)) && (
          <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
            <ToggleButtonGroup size="small" disabled={disabled}>
              {!hiddenItems.has('text-color') && (
                <Tooltip title="Text Color">
                  <ToggleButton
                    value="textColor"
                    data-toolbar-item="text-color"
                    selected={Boolean(textColorAnchor)}
                    onClick={(e) => setTextColorAnchor(textColorAnchor ? null : e.currentTarget)}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25 }}>
                      <FormatColorText fontSize="small" />
                      {currentColor && (
                        <Box
                          sx={{
                            width: 12,
                            height: 12,
                            borderRadius: 0.5,
                            border: 1,
                            borderColor: 'divider',
                            bgcolor: currentColor,
                          }}
                        />
                      )}
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('bg-color') && (
                <Tooltip title="Background Color">
                  <ToggleButton
                    value="bgColor"
                    data-toolbar-item="bg-color"
                    selected={Boolean(bgColorAnchor)}
                    onClick={(e) => setBgColorAnchor(bgColorAnchor ? null : e.currentTarget)}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25 }}>
                      <FormatPaint fontSize="small" />
                      {currentBgColor && (
                        <Box
                          sx={{
                            width: 12,
                            height: 12,
                            borderRadius: 0.5,
                            border: 1,
                            borderColor: 'divider',
                            bgcolor: currentBgColor,
                          }}
                        />
                      )}
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('highlight') && (
                <Tooltip title="Highlight">
                  <ToggleButton
                    value="highlight"
                    data-toolbar-item="highlight"
                    selected={editor.isActive('highlight')}
                    onClick={() => editor.chain().focus().toggleHighlight().run()}
                  >
                    <Highlight fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          </Box>
        )}
        {/* align-lists: alignment, lists, indent */}
        {!['align', 'bullet-list', 'ordered-list', 'indent', 'outdent', 'task-list'].every((id) => hiddenItems.has(id)) && (
          <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
            <ToggleButtonGroup size="small" disabled={disabled}>
              {!hiddenItems.has('align') && (
                <Tooltip title="Alignment">
                  <ToggleButton
                    value="align"
                    data-toolbar-item="align"
                    selected={Boolean(alignAnchor)}
                    onClick={(e) => setAlignAnchor(alignAnchor ? null : e.currentTarget)}
                    sx={{ pr: 0.25 }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      {React.createElement(ALIGN_OPTIONS.find((o) => o.value === currentAlign)?.icon ?? FormatAlignLeft, {
                        fontSize: 'small',
                      })}
                      <ArrowDropDown sx={{ fontSize: 18 }} />
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('bullet-list') && (
                <Tooltip title="Bullet List">
                  <ToggleButton
                    value="bulletList"
                    data-toolbar-item="bullet-list"
                    selected={editor.isActive('bulletList')}
                    onClick={() => editor.chain().focus().toggleBulletList().run()}
                  >
                    <FormatListBulleted fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('ordered-list') && (
                <Tooltip title="Numbered List">
                  <ToggleButton
                    value="orderedList"
                    data-toolbar-item="ordered-list"
                    selected={editor.isActive('orderedList')}
                    onClick={() => editor.chain().focus().toggleOrderedList().run()}
                  >
                    <FormatListNumbered fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('indent') && (
                <Tooltip title="Indent">
                  <ToggleButton
                    value="indent"
                    data-toolbar-item="indent"
                    onClick={indent}
                  >
                    <FormatIndentIncrease fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('outdent') && (
                <Tooltip title="Outdent">
                  <ToggleButton
                    value="outdent"
                    data-toolbar-item="outdent"
                    onClick={outdent}
                  >
                    <FormatIndentDecrease fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('task-list') && (
                <Tooltip title="Todo List">
                  <ToggleButton
                    value="taskList"
                    data-toolbar-item="task-list"
                    selected={editor.isActive('taskList')}
                    onClick={() => editor.chain().focus().toggleTaskList().run()}
                  >
                    <ChecklistRtl fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          </Box>
        )}
        {/* Alignment dropdown menu — always rendered (uses a portal) */}
        <Menu
          anchorEl={alignAnchor}
          open={Boolean(alignAnchor)}
          onClose={() => setAlignAnchor(null)}
          anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        >
          {ALIGN_OPTIONS.map((o) => (
            <MenuItem
              key={o.value}
              selected={currentAlign === o.value}
              onClick={() => {
                editor.chain().focus().setTextAlign(o.value).run();
                setAlignAnchor(null);
              }}
            >
              <Box component={o.icon} sx={{ mr: 1, fontSize: 20 }} />
              {o.label}
            </MenuItem>
          ))}
        </Menu>
        {/* insert: link, image, blockquote, code, subscript, superscript */}
        {!['link', 'image', 'blockquote', 'code', 'code-block', 'subscript', 'superscript'].every((id) => hiddenItems.has(id)) && (
          <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
            <ToggleButtonGroup size="small" disabled={disabled}>
              {!hiddenItems.has('link') && (
                <Tooltip title="Link">
                  <ToggleButton
                    value="link"
                    data-toolbar-item="link"
                    selected={editor.isActive('link')}
                    onClick={() => onOpenLinkPopover?.()}
                  >
                    <LinkIcon fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('image') && (
                <Tooltip title="Image">
                  <ToggleButton
                    value="image"
                    data-toolbar-item="image"
                    onClick={() => onOpenImagePopover?.()}
                  >
                    <ImageIcon fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('blockquote') && (
                <Tooltip title="Blockquote">
                  <ToggleButton
                    value="blockquote"
                    data-toolbar-item="blockquote"
                    selected={editor.isActive('blockquote')}
                    onClick={() => editor.chain().focus().toggleBlockquote().run()}
                  >
                    <FormatQuote fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('code') && (
                <Tooltip title="Code">
                  <ToggleButton
                    value="code"
                    data-toolbar-item="code"
                    selected={editor.isActive('code')}
                    onClick={() => editor.chain().focus().toggleCode().run()}
                  >
                    <Code fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('code-block') && (
                <Tooltip title="Code Block">
                  <ToggleButton
                    value="codeBlock"
                    data-toolbar-item="code-block"
                    selected={editor.isActive('codeBlock')}
                    onClick={() => editor.chain().focus().toggleCodeBlock().run()}
                  >
                    <DataObject fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('subscript') && (
                <Tooltip title="Subscript">
                  <ToggleButton
                    value="subscript"
                    data-toolbar-item="subscript"
                    selected={editor.isActive('subscript')}
                    onClick={() => editor.chain().focus().toggleSubscript().run()}
                  >
                    <SubscriptIcon fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('superscript') && (
                <Tooltip title="Superscript">
                  <ToggleButton
                    value="superscript"
                    data-toolbar-item="superscript"
                    selected={editor.isActive('superscript')}
                    onClick={() => editor.chain().focus().toggleSuperscript().run()}
                  >
                    <SuperscriptIcon fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          </Box>
        )}
        {/* block: table, page break, horizontal rule */}
        {!['table', 'page-break', 'hr'].every((id) => hiddenItems.has(id)) && (
          <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
            <ToggleButtonGroup size="small" disabled={disabled}>
              {!hiddenItems.has('table') && (
                <Tooltip title="Table">
                  <ToggleButton
                    value="table"
                    data-toolbar-item="table"
                    selected={Boolean(tableGridAnchor)}
                    onClick={(e) => setTableGridAnchor(tableGridAnchor ? null : e.currentTarget)}
                  >
                    <TableChart fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('page-break') && (
                <Tooltip title="Page Break">
                  <ToggleButton
                    value="pageBreak"
                    data-toolbar-item="page-break"
                    onClick={insertPageBreak}
                  >
                    <ViewAgenda fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {!hiddenItems.has('hr') && (
                <Tooltip title="Horizontal Rule">
                  <ToggleButton
                    value="hr"
                    data-toolbar-item="hr"
                    onClick={() => editor.chain().focus().setHorizontalRule().run()}
                  >
                    <HorizontalRule fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          </Box>
        )}
        {/* source: HTML source mode (optional) */}
        {onToggleSourceMode && !hiddenItems.has('source') && (
          <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
            <ToggleButtonGroup size="small" disabled={disabled}>
              <Tooltip title="Source HTML">
                <ToggleButton
                  value="sourceMode"
                  data-toolbar-item="source"
                  selected={isSourceMode}
                  onClick={onToggleSourceMode}
                >
                  <Html fontSize="small" />
                </ToggleButton>
              </Tooltip>
            </ToggleButtonGroup>
          </Box>
        )}
        {/* history: undo, redo */}
        {!['undo', 'redo'].every((id) => hiddenItems.has(id)) && (
          <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
            <ToggleButtonGroup size="small" disabled={disabled}>
              {!hiddenItems.has('undo') && (
                <Tooltip title="Undo">
                  <span>
                    <IconButton
                      size="small"
                      data-toolbar-item="undo"
                      onClick={() => editor.chain().focus().undo().run()}
                      disabled={!editor.can().undo()}
                    >
                      <Undo fontSize="small" />
                    </IconButton>
                  </span>
                </Tooltip>
              )}
              {!hiddenItems.has('redo') && (
                <Tooltip title="Redo">
                  <span>
                    <IconButton
                      size="small"
                      data-toolbar-item="redo"
                      onClick={() => editor.chain().focus().redo().run()}
                      disabled={!editor.can().redo()}
                    >
                      <Redo fontSize="small" />
                    </IconButton>
                  </span>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          </Box>
        )}
        {hiddenItems.size > 0 && (
          <Tooltip title="More">
            <IconButton
              size="small"
              aria-label="More"
              aria-haspopup="menu"
              aria-expanded={Boolean(moreAnchor)}
              onClick={(e) => setMoreAnchor(moreAnchor ? null : e.currentTarget)}
              sx={{ ml: 0.5 }}
            >
              <MoreVert fontSize="small" />
            </IconButton>
          </Tooltip>
        )}
      </Box>
      {/* === Overflow menu — horizontal icon popover === */}
      <Popover
        open={Boolean(moreAnchor)}
        anchorEl={moreAnchor}
        onClose={() => setMoreAnchor(null)}
        disableRestoreFocus={hiddenItems.size === 0}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        slotProps={{ paper: { sx: { p: 0.5 } } }}
      >
        <Box
          onMouseDown={(e) => e.preventDefault()}
          sx={{
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            gap: 0.5,
          }}
        >
          {/* heading */}
          {hiddenItems.has('heading-select') && (
            <Select
              size="small"
              disabled={disabled}
              value={currentHeading}
              onChange={(e) => {
                const opt = HEADING_OPTIONS.find((o) => o.value === e.target.value);
                if (!opt) return;
                if (opt.level === null) {
                  editor.chain().focus().setParagraph().run();
                } else {
                  editor.chain().focus().toggleHeading({ level: opt.level }).run();
                }
              }}
              displayEmpty
              sx={{ minWidth: 130, height: 32 }}
            >
              {HEADING_OPTIONS.map((o) => (
                <MenuItem key={o.value} value={o.value}>
                  {o.label}
                </MenuItem>
              ))}
            </Select>
          )}
          {/* font-format */}
          {['font-family', 'font-size', 'bold', 'italic', 'underline', 'strike'].some((id) => hiddenItems.has(id)) && (
            <ToggleButtonGroup size="small" disabled={disabled}>
              {hiddenItems.has('font-family') && (
                <Tooltip title="Font Family">
                  <ToggleButton
                    value="fontFamily"
                    selected={Boolean(fontFamilyAnchor)}
                    onClick={(e) => setFontFamilyAnchor(fontFamilyAnchor ? null : e.currentTarget)}
                    sx={{ pr: 0.25 }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <FontDownload fontSize="small" />
                      <ArrowDropDown sx={{ fontSize: 18 }} />
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('font-size') && (
                <Tooltip title="Font Size">
                  <ToggleButton
                    value="fontSize"
                    selected={Boolean(fontSizeAnchor)}
                    onClick={(e) => setFontSizeAnchor(fontSizeAnchor ? null : e.currentTarget)}
                    sx={{ pr: 0.25 }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <FormatSize fontSize="small" />
                      <ArrowDropDown sx={{ fontSize: 18 }} />
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('bold') && (
                <Tooltip title="Bold">
                  <ToggleButton
                    value="bold"
                    selected={editor.isActive('bold')}
                    onClick={() => editor.chain().focus().toggleBold().run()}
                  >
                    <FormatBold fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('italic') && (
                <Tooltip title="Italic">
                  <ToggleButton
                    value="italic"
                    selected={editor.isActive('italic')}
                    onClick={() => editor.chain().focus().toggleItalic().run()}
                  >
                    <FormatItalic fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('underline') && (
                <Tooltip title="Underline">
                  <ToggleButton
                    value="underline"
                    selected={editor.isActive('underline')}
                    onClick={() => editor.chain().focus().toggleUnderline().run()}
                  >
                    <FormatUnderlined fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('strike') && (
                <Tooltip title="Strikethrough">
                  <ToggleButton
                    value="strike"
                    selected={editor.isActive('strike')}
                    onClick={() => editor.chain().focus().toggleStrike().run()}
                  >
                    <FormatStrikethrough fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          )}
          {/* color */}
          {['text-color', 'bg-color', 'highlight'].some((id) => hiddenItems.has(id)) && (
            <ToggleButtonGroup size="small" disabled={disabled}>
              {hiddenItems.has('text-color') && (
                <Tooltip title="Text Color">
                  <ToggleButton
                    value="textColor"
                    selected={Boolean(textColorAnchor)}
                    onClick={(e) => setTextColorAnchor(textColorAnchor ? null : e.currentTarget)}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25 }}>
                      <FormatColorText fontSize="small" />
                      {currentColor && (
                        <Box
                          sx={{
                            width: 12,
                            height: 12,
                            borderRadius: 0.5,
                            border: 1,
                            borderColor: 'divider',
                            bgcolor: currentColor,
                          }}
                        />
                      )}
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('bg-color') && (
                <Tooltip title="Background Color">
                  <ToggleButton
                    value="bgColor"
                    selected={Boolean(bgColorAnchor)}
                    onClick={(e) => setBgColorAnchor(bgColorAnchor ? null : e.currentTarget)}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25 }}>
                      <FormatPaint fontSize="small" />
                      {currentBgColor && (
                        <Box
                          sx={{
                            width: 12,
                            height: 12,
                            borderRadius: 0.5,
                            border: 1,
                            borderColor: 'divider',
                            bgcolor: currentBgColor,
                          }}
                        />
                      )}
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('highlight') && (
                <Tooltip title="Highlight">
                  <ToggleButton
                    value="highlight"
                    selected={editor.isActive('highlight')}
                    onClick={() => editor.chain().focus().toggleHighlight().run()}
                  >
                    <Highlight fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          )}
          {/* align-lists */}
          {['align', 'bullet-list', 'ordered-list', 'indent', 'outdent', 'task-list'].some((id) => hiddenItems.has(id)) && (
            <ToggleButtonGroup size="small" disabled={disabled}>
              {hiddenItems.has('align') && (
                <Tooltip title="Alignment">
                  <ToggleButton
                    value="align"
                    selected={Boolean(alignAnchor)}
                    onClick={(e) => setAlignAnchor(alignAnchor ? null : e.currentTarget)}
                    sx={{ pr: 0.25 }}
                  >
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      {React.createElement(ALIGN_OPTIONS.find((o) => o.value === currentAlign)?.icon ?? FormatAlignLeft, {
                        fontSize: 'small',
                      })}
                      <ArrowDropDown sx={{ fontSize: 18 }} />
                    </Box>
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('bullet-list') && (
                <Tooltip title="Bullet List">
                  <ToggleButton
                    value="bulletList"
                    selected={editor.isActive('bulletList')}
                    onClick={() => editor.chain().focus().toggleBulletList().run()}
                  >
                    <FormatListBulleted fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('ordered-list') && (
                <Tooltip title="Numbered List">
                  <ToggleButton
                    value="orderedList"
                    selected={editor.isActive('orderedList')}
                    onClick={() => editor.chain().focus().toggleOrderedList().run()}
                  >
                    <FormatListNumbered fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('indent') && (
                <Tooltip title="Indent">
                  <ToggleButton value="indent" onClick={indent}>
                    <FormatIndentIncrease fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('outdent') && (
                <Tooltip title="Outdent">
                  <ToggleButton value="outdent" onClick={outdent}>
                    <FormatIndentDecrease fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('task-list') && (
                <Tooltip title="Todo List">
                  <ToggleButton
                    value="taskList"
                    selected={editor.isActive('taskList')}
                    onClick={() => editor.chain().focus().toggleTaskList().run()}
                  >
                    <ChecklistRtl fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          )}
          {/* insert */}
          {['link', 'image', 'blockquote', 'code', 'code-block', 'subscript', 'superscript'].some((id) => hiddenItems.has(id)) && (
            <ToggleButtonGroup size="small" disabled={disabled}>
              {hiddenItems.has('link') && (
                <Tooltip title="Link">
                  <ToggleButton
                    value="link"
                    selected={editor.isActive('link')}
                    onClick={() => onOpenLinkPopover?.()}
                  >
                    <LinkIcon fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('image') && (
                <Tooltip title="Image">
                  <ToggleButton value="image" onClick={() => onOpenImagePopover?.()}>
                    <ImageIcon fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('blockquote') && (
                <Tooltip title="Blockquote">
                  <ToggleButton
                    value="blockquote"
                    selected={editor.isActive('blockquote')}
                    onClick={() => editor.chain().focus().toggleBlockquote().run()}
                  >
                    <FormatQuote fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('code') && (
                <Tooltip title="Code">
                  <ToggleButton
                    value="code"
                    selected={editor.isActive('code')}
                    onClick={() => editor.chain().focus().toggleCode().run()}
                  >
                    <Code fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('code-block') && (
                <Tooltip title="Code Block">
                  <ToggleButton
                    value="codeBlock"
                    selected={editor.isActive('codeBlock')}
                    onClick={() => editor.chain().focus().toggleCodeBlock().run()}
                  >
                    <DataObject fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('subscript') && (
                <Tooltip title="Subscript">
                  <ToggleButton
                    value="subscript"
                    selected={editor.isActive('subscript')}
                    onClick={() => editor.chain().focus().toggleSubscript().run()}
                  >
                    <SubscriptIcon fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('superscript') && (
                <Tooltip title="Superscript">
                  <ToggleButton
                    value="superscript"
                    selected={editor.isActive('superscript')}
                    onClick={() => editor.chain().focus().toggleSuperscript().run()}
                  >
                    <SuperscriptIcon fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          )}
          {/* block */}
          {['table', 'page-break', 'hr'].some((id) => hiddenItems.has(id)) && (
            <ToggleButtonGroup size="small" disabled={disabled}>
              {hiddenItems.has('table') && (
                <Tooltip title="Table">
                  <ToggleButton
                    value="table"
                    selected={Boolean(tableGridAnchor)}
                    onClick={(e) => setTableGridAnchor(tableGridAnchor ? null : e.currentTarget)}
                  >
                    <TableChart fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('page-break') && (
                <Tooltip title="Page Break">
                  <ToggleButton value="pageBreak" onClick={insertPageBreak}>
                    <ViewAgenda fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
              {hiddenItems.has('hr') && (
                <Tooltip title="Horizontal Rule">
                  <ToggleButton value="hr" onClick={() => editor.chain().focus().setHorizontalRule().run()}>
                    <HorizontalRule fontSize="small" />
                  </ToggleButton>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          )}
          {/* source */}
          {onToggleSourceMode && hiddenItems.has('source') && (
            <ToggleButtonGroup size="small" disabled={disabled}>
              <Tooltip title="Source HTML">
                <ToggleButton
                  value="sourceMode"
                  selected={isSourceMode}
                  onClick={onToggleSourceMode}
                >
                  <Html fontSize="small" />
                </ToggleButton>
              </Tooltip>
            </ToggleButtonGroup>
          )}
          {/* history */}
          {['undo', 'redo'].some((id) => hiddenItems.has(id)) && (
            <ToggleButtonGroup size="small" disabled={disabled}>
              {hiddenItems.has('undo') && (
                <Tooltip title="Undo">
                  <span>
                    <IconButton
                      size="small"
                      onClick={() => editor.chain().focus().undo().run()}
                      disabled={!editor.can().undo()}
                    >
                      <Undo fontSize="small" />
                    </IconButton>
                  </span>
                </Tooltip>
              )}
              {hiddenItems.has('redo') && (
                <Tooltip title="Redo">
                  <span>
                    <IconButton
                      size="small"
                      onClick={() => editor.chain().focus().redo().run()}
                      disabled={!editor.can().redo()}
                    >
                      <Redo fontSize="small" />
                    </IconButton>
                  </span>
                </Tooltip>
              )}
            </ToggleButtonGroup>
          )}
        </Box>
      </Popover>
      <Popover
        open={Boolean(textColorAnchor)}
        anchorEl={textColorAnchor}
        onClose={() => setTextColorAnchor(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Box sx={{ p: 1, borderBottom: 1, borderColor: 'divider', display: 'flex', justifyContent: 'center' }}>
          <MenuItem
            sx={{ borderRadius: 1, typography: 'body2', py: 0.5, flexGrow: 1, justifyContent: 'center' }}
            onClick={() => {
              editor.chain().focus().unsetColor().run();
              setTextColorAnchor(null);
            }}
          >
            Reset Default Color
          </MenuItem>
        </Box>
        <SketchPicker
          color={currentColor || '#000000'}
          onChangeComplete={(color) => {
            editor.chain().focus().setColor(color.hex).run();
          }}
        />
      </Popover>
      <Popover
        open={Boolean(bgColorAnchor)}
        anchorEl={bgColorAnchor}
        onClose={() => setBgColorAnchor(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      >
        <Box sx={{ p: 1, borderBottom: 1, borderColor: 'divider', display: 'flex', justifyContent: 'center' }}>
          <MenuItem
            sx={{ borderRadius: 1, typography: 'body2', py: 0.5, flexGrow: 1, justifyContent: 'center' }}
            onClick={() => {
              editor.chain().focus().unsetBackgroundColor().run();
              setBgColorAnchor(null);
            }}
          >
            Reset Background Color
          </MenuItem>
        </Box>
        <SketchPicker
          color={currentBgColor || '#ffff00'}
          onChangeComplete={(color) => {
            editor.chain().focus().setBackgroundColor(color.hex).run();
          }}
        />
      </Popover>
      <TableGridPicker
        anchorEl={tableGridAnchor}
        open={Boolean(tableGridAnchor)}
        onClose={() => setTableGridAnchor(null)}
        editor={editor}
      />
    </Box>
  );
};
