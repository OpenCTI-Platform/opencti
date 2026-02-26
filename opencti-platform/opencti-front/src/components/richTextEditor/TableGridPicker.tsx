import type { Editor } from '@tiptap/react';
import React, { useState, useCallback, useRef, useEffect } from 'react';
import Box from '@mui/material/Box';
import Popover from '@mui/material/Popover';
import Typography from '@mui/material/Typography';
import Checkbox from '@mui/material/Checkbox';
import FormControlLabel from '@mui/material/FormControlLabel';

const MAX_ROWS = 10;
const MAX_COLS = 10;
const CELL_SIZE = 18;
const CELL_GAP = 2;

interface TableGridPickerProps {
  anchorEl: HTMLElement | null;
  open: boolean;
  onClose: () => void;
  editor: Editor;
}

/**
 * A visual rows×cols grid picker for inserting tables.
 *
 * Supports full keyboard navigation:
 * - Arrow keys move the highlighted selection
 * - Enter inserts the table at the highlighted size
 * - Escape closes the picker
 */
export const TableGridPicker: React.FC<TableGridPickerProps> = ({
  anchorEl,
  open,
  onClose,
  editor,
}) => {
  const [hoverRow, setHoverRow] = useState(0);
  const [hoverCol, setHoverCol] = useState(0);
  const [withHeaderRow, setWithHeaderRow] = useState(true);
  const gridRef = useRef<HTMLDivElement>(null);

  // Reset highlight when the picker opens
  useEffect(() => {
    if (open) {
      setHoverRow(0);
      setHoverCol(0);
    }
  }, [open]);

  // Auto-focus the grid so keyboard works immediately
  useEffect(() => {
    if (open) {
      // Small delay to let the popover render before focusing
      const timer = setTimeout(() => gridRef.current?.focus(), 50);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [open]);

  const insertTable = useCallback(
    (rows: number, cols: number) => {
      editor.chain().focus().insertTable({ rows, cols, withHeaderRow }).run();
      onClose();
    },
    [editor, withHeaderRow, onClose],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      switch (e.key) {
        case 'ArrowRight':
          e.preventDefault();
          setHoverCol((c) => Math.min(c + 1, MAX_COLS - 1));
          break;
        case 'ArrowLeft':
          e.preventDefault();
          setHoverCol((c) => Math.max(c - 1, 0));
          break;
        case 'ArrowDown':
          e.preventDefault();
          setHoverRow((r) => Math.min(r + 1, MAX_ROWS - 1));
          break;
        case 'ArrowUp':
          e.preventDefault();
          setHoverRow((r) => Math.max(r - 1, 0));
          break;
        case 'Enter':
          e.preventDefault();
          insertTable(hoverRow + 1, hoverCol + 1);
          break;
        case 'Escape':
          e.preventDefault();
          onClose();
          break;
        default:
          break;
      }
    },
    [hoverRow, hoverCol, insertTable, onClose],
  );

  const isHighlighted = (row: number, col: number) => row <= hoverRow && col <= hoverCol;

  return (
    <Popover
      open={open}
      anchorEl={anchorEl}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
      transformOrigin={{ vertical: 'top', horizontal: 'left' }}
      slotProps={{ paper: { sx: { mt: 0.5 } } }}
    >
      <Box sx={{ p: 1.5, minWidth: MAX_COLS * (CELL_SIZE + CELL_GAP) + 12 }}>
        <Box
          ref={gridRef}
          tabIndex={0}
          role="grid"
          aria-label="Table size picker"
          onKeyDown={handleKeyDown}
          sx={{
            outline: 'none',
            display: 'inline-grid',
            gridTemplateColumns: `repeat(${MAX_COLS}, ${CELL_SIZE}px)`,
            gap: `${CELL_GAP}px`,
          }}
        >
          {Array.from({ length: MAX_ROWS }, (_, r) =>
            Array.from({ length: MAX_COLS }, (_, c) => (
              <Box
                key={`${r}-${c}`}
                role="gridcell"
                aria-label={`${r + 1} rows × ${c + 1} columns`}
                aria-selected={isHighlighted(r, c)}
                onMouseEnter={() => {
                  setHoverRow(r);
                  setHoverCol(c);
                }}
                onClick={() => insertTable(r + 1, c + 1)}
                sx={{
                  width: CELL_SIZE,
                  height: CELL_SIZE,
                  border: '1px solid',
                  borderColor: isHighlighted(r, c) ? 'primary.main' : 'divider',
                  backgroundColor: isHighlighted(r, c) ? 'primary.main' : 'transparent',
                  opacity: isHighlighted(r, c) ? 0.45 : 1,
                  cursor: 'pointer',
                  borderRadius: '2px',
                  transition: 'background-color 0.08s, border-color 0.08s',
                }}
              />
            )),
          )}
        </Box>

        <Typography
          variant="caption"
          sx={{ display: 'block', textAlign: 'center', mt: 1, fontWeight: 500 }}
        >
          {hoverRow + 1} × {hoverCol + 1}
        </Typography>

        <FormControlLabel
          control={(
            <Checkbox
              size="small"
              checked={withHeaderRow}
              onChange={(e) => setWithHeaderRow(e.target.checked)}
            />
          )}
          label={<Typography variant="caption">Header row</Typography>}
          sx={{ mt: 0.5, ml: 0 }}
        />
      </Box>
    </Popover>
  );
};
