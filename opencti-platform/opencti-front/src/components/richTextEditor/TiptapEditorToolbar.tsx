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

  return (
    <Box
      onMouseDown={(e) => e.preventDefault()}
      sx={{
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: 0.5,
        p: 0.5,
        borderBottom: 1,
        borderColor: 'divider',
        minHeight: 40,
      }}
    >
      {/* legacy editor order: heading, fontFamily, fontSize, alignment, pageBreak */}
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
      <ToggleButtonGroup size="small" disabled={disabled}>
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
        <Tooltip title="Bold">
          <ToggleButton
            value="bold"
            selected={editor.isActive('bold')}
            onClick={() => editor.chain().focus().toggleBold().run()}
          >
            <FormatBold fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Italic">
          <ToggleButton
            value="italic"
            selected={editor.isActive('italic')}
            onClick={() => editor.chain().focus().toggleItalic().run()}
          >
            <FormatItalic fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Underline">
          <ToggleButton
            value="underline"
            selected={editor.isActive('underline')}
            onClick={() => editor.chain().focus().toggleUnderline().run()}
          >
            <FormatUnderlined fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Strikethrough">
          <ToggleButton
            value="strike"
            selected={editor.isActive('strike')}
            onClick={() => editor.chain().focus().toggleStrike().run()}
          >
            <FormatStrikethrough fontSize="small" />
          </ToggleButton>
        </Tooltip>
      </ToggleButtonGroup>
      <ToggleButtonGroup size="small" disabled={disabled}>
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
        <Tooltip title="Highlight">
          <ToggleButton
            value="highlight"
            selected={editor.isActive('highlight')}
            onClick={() => editor.chain().focus().toggleHighlight().run()}
          >
            <Highlight fontSize="small" />
          </ToggleButton>
        </Tooltip>
      </ToggleButtonGroup>
      <ToggleButtonGroup size="small" disabled={disabled}>
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
        <Tooltip title="Bullet List">
          <ToggleButton
            value="bulletList"
            selected={editor.isActive('bulletList')}
            onClick={() => editor.chain().focus().toggleBulletList().run()}
          >
            <FormatListBulleted fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Numbered List">
          <ToggleButton
            value="orderedList"
            selected={editor.isActive('orderedList')}
            onClick={() => editor.chain().focus().toggleOrderedList().run()}
          >
            <FormatListNumbered fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Indent">
          <ToggleButton value="indent" onClick={indent}>
            <FormatIndentIncrease fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Outdent">
          <ToggleButton value="outdent" onClick={outdent}>
            <FormatIndentDecrease fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Todo List">
          <ToggleButton
            value="taskList"
            selected={editor.isActive('taskList')}
            onClick={() => editor.chain().focus().toggleTaskList().run()}
          >
            <ChecklistRtl fontSize="small" />
          </ToggleButton>
        </Tooltip>
      </ToggleButtonGroup>
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
      {/* link, imageInsert, blockQuote, code, codeBlock, subscript, superscript, horizontalLine */}
      <ToggleButtonGroup size="small" disabled={disabled}>
        <Tooltip title="Link">
          <ToggleButton
            value="link"
            selected={editor.isActive('link')}
            onClick={() => onOpenLinkPopover?.()}
          >
            <LinkIcon fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Image">
          <ToggleButton value="image" onClick={() => onOpenImagePopover?.()}>
            <ImageIcon fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Blockquote">
          <ToggleButton
            value="blockquote"
            selected={editor.isActive('blockquote')}
            onClick={() => editor.chain().focus().toggleBlockquote().run()}
          >
            <FormatQuote fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Code">
          <ToggleButton
            value="code"
            selected={editor.isActive('code')}
            onClick={() => editor.chain().focus().toggleCode().run()}
          >
            <Code fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Code Block">
          <ToggleButton
            value="codeBlock"
            selected={editor.isActive('codeBlock')}
            onClick={() => editor.chain().focus().toggleCodeBlock().run()}
          >
            <DataObject fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Subscript">
          <ToggleButton
            value="subscript"
            selected={editor.isActive('subscript')}
            onClick={() => editor.chain().focus().toggleSubscript().run()}
          >
            <SubscriptIcon fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Superscript">
          <ToggleButton
            value="superscript"
            selected={editor.isActive('superscript')}
            onClick={() => editor.chain().focus().toggleSuperscript().run()}
          >
            <SuperscriptIcon fontSize="small" />
          </ToggleButton>
        </Tooltip>
      </ToggleButtonGroup>
      <ToggleButtonGroup size="small" disabled={disabled}>
        <Tooltip title="Table">
          <ToggleButton
            value="table"
            selected={Boolean(tableGridAnchor)}
            onClick={(e) => setTableGridAnchor(tableGridAnchor ? null : e.currentTarget)}
          >
            <TableChart fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Page Break">
          <ToggleButton value="pageBreak" onClick={insertPageBreak}>
            <ViewAgenda fontSize="small" />
          </ToggleButton>
        </Tooltip>
        <Tooltip title="Horizontal Rule">
          <ToggleButton value="hr" onClick={() => editor.chain().focus().setHorizontalRule().run()}>
            <HorizontalRule fontSize="small" />
          </ToggleButton>
        </Tooltip>
      </ToggleButtonGroup>
      {onToggleSourceMode && (
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
      {/* undo, redo */}
      <ToggleButtonGroup size="small" disabled={disabled} sx={{ flexWrap: 'wrap' }}>
        <Tooltip title="Undo">
          <IconButton
            size="small"
            onClick={() => editor.chain().focus().undo().run()}
            disabled={!editor.can().undo()}
          >
            <Undo fontSize="small" />
          </IconButton>
        </Tooltip>
        <Tooltip title="Redo">
          <IconButton
            size="small"
            onClick={() => editor.chain().focus().redo().run()}
            disabled={!editor.can().redo()}
          >
            <Redo fontSize="small" />
          </IconButton>
        </Tooltip>
      </ToggleButtonGroup>
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
