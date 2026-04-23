import type { Editor } from '@tiptap/react';
import React, { useCallback } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Divider from '@mui/material/Divider';
import ListSubheader from '@mui/material/ListSubheader';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { DeleteOutline, MergeType, SplitscreenOutlined, BorderTopOutlined, BorderLeftOutlined, TableChart, AddOutlined, RemoveOutlined } from '@mui/icons-material';

interface TableContextMenuProps {
  editor: Editor;
  open: boolean;
  position: { top: number; left: number } | null;
  onClose: () => void;
}

const subheaderSx = { lineHeight: '28px', fontSize: '0.72rem', fontWeight: 700 } as const;

/**
 * Context menu shown on right-click inside a table.
 *
 * Exposes all prosemirror-tables operations available via @tiptap/extension-table:
 * row/column CRUD, header toggles, merge, split, nested table insertion, and delete table.
 */
export const TableContextMenu: React.FC<TableContextMenuProps> = ({
  editor,
  open,
  position,
  onClose,
}) => {
  const runAndClose = useCallback(
    (command: () => void) => {
      command();
      onClose();
    },
    [onClose],
  );

  const canMerge = editor.can().mergeCells();

  return (
    <Menu
      open={open}
      onClose={onClose}
      anchorReference="anchorPosition"
      anchorPosition={position ? { top: position.top, left: position.left } : undefined}
      /* Prevent MUI from restoring focus to the editor on close —
         that would trigger ProseMirror's scrollIntoView and jump to the top. */
      disableRestoreFocus
      disableAutoFocus
      slotProps={{ paper: { sx: { minWidth: 220 } } }}
    >
      {/* ── Row operations ── */}
      <ListSubheader sx={subheaderSx}>Row</ListSubheader>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().addRowBefore().run())}
      >
        <ListItemIcon><AddOutlined fontSize="small" /></ListItemIcon>
        <ListItemText>Add row above</ListItemText>
      </MenuItem>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().addRowAfter().run())}
      >
        <ListItemIcon><AddOutlined fontSize="small" /></ListItemIcon>
        <ListItemText>Add row below</ListItemText>
      </MenuItem>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().deleteRow().run())}
      >
        <ListItemIcon><RemoveOutlined fontSize="small" /></ListItemIcon>
        <ListItemText>Delete row</ListItemText>
      </MenuItem>

      <Divider />

      {/* ── Column operations ── */}
      <ListSubheader sx={subheaderSx}>Column</ListSubheader>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().addColumnBefore().run())}
      >
        <ListItemIcon><AddOutlined fontSize="small" /></ListItemIcon>
        <ListItemText>Add column before</ListItemText>
      </MenuItem>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().addColumnAfter().run())}
      >
        <ListItemIcon><AddOutlined fontSize="small" /></ListItemIcon>
        <ListItemText>Add column after</ListItemText>
      </MenuItem>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().deleteColumn().run())}
      >
        <ListItemIcon><RemoveOutlined fontSize="small" /></ListItemIcon>
        <ListItemText>Delete column</ListItemText>
      </MenuItem>

      <Divider />

      {/* ── Header toggles ── */}
      <ListSubheader sx={subheaderSx}>Header</ListSubheader>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().toggleHeaderRow().run())}
      >
        <ListItemIcon><BorderTopOutlined fontSize="small" /></ListItemIcon>
        <ListItemText>Toggle header row</ListItemText>
      </MenuItem>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().toggleHeaderColumn().run())}
      >
        <ListItemIcon><BorderLeftOutlined fontSize="small" /></ListItemIcon>
        <ListItemText>Toggle header column</ListItemText>
      </MenuItem>

      <Divider />

      {/* ── Merge / Split ── */}
      <ListSubheader sx={subheaderSx}>Cells</ListSubheader>
      <MenuItem
        dense
        disabled={!canMerge}
        onClick={() => runAndClose(() => editor.chain().focus().mergeCells().run())}
      >
        <ListItemIcon><MergeType fontSize="small" /></ListItemIcon>
        <ListItemText>Merge cells</ListItemText>
      </MenuItem>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().splitCellHorizontal().run())}
      >
        <ListItemIcon>
          <SplitscreenOutlined fontSize="small" />
        </ListItemIcon>
        <ListItemText>Split cell horizontally</ListItemText>
      </MenuItem>
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().splitCellVertical().run())}
      >
        <ListItemIcon>
          <SplitscreenOutlined fontSize="small" sx={{ transform: 'rotate(90deg)' }} />
        </ListItemIcon>
        <ListItemText>Split cell vertically</ListItemText>
      </MenuItem>

      <Divider />

      {/* ── Nested table ── */}
      <MenuItem
        dense
        onClick={() =>
          runAndClose(() =>
            editor
              .chain()
              .focus()
              .insertTable({ rows: 2, cols: 2, withHeaderRow: true })
              .run(),
          )}
      >
        <ListItemIcon><TableChart fontSize="small" /></ListItemIcon>
        <ListItemText>Insert nested table</ListItemText>
      </MenuItem>

      <Divider />

      {/* ── Delete table ── */}
      <MenuItem
        dense
        onClick={() => runAndClose(() => editor.chain().focus().deleteTable().run())}
        sx={{ color: 'error.main' }}
      >
        <ListItemIcon><DeleteOutline fontSize="small" color="error" /></ListItemIcon>
        <ListItemText>Delete table</ListItemText>
      </MenuItem>
    </Menu>
  );
};
