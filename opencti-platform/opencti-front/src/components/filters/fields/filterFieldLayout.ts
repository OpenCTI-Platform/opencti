import { CSSProperties } from 'react';
import { Theme } from '@mui/material/styles';

/**
 * Column geometry shared by every filter row.
 *
 * The first two columns are sized in percentage of the row, on purpose: a composite filter
 * (`regardingOf`) renders one value column more than a simple filter, so ratio-based flex
 * would give those rows a different key/condition width and break the vertical alignment of
 * the whole group panel. Percentages keep the two leading columns identical in every row and
 * let the value columns share whatever is left.
 */
export const FILTER_ROW_COLUMN_FLEX = {
  key: '0 0 22%',
  operator: '0 0 18%',
  /** Single value column, takes the remaining width. */
  value: '1 1 auto',
  /** One of the two value columns of a composite filter, sharing the remaining width evenly. */
  compositeValue: '1 1 0',
} as const;

/** Fixed width of the floating value editors: it never grows with the content (e.g. many autocomplete chips). */
export const FILTER_VALUE_POPOVER_WIDTH = 500;

/**
 * Outlined-field look-alike box shared by the two clickable value boxes of a nested-filter-group
 * row that open a popover instead of showing their editor inline (DateRangeFilter's summary box,
 * FilterRowCompositeValue's dynamic-filter button): border, radius, cursor and box-sizing match
 * MUI's outlined TextField. Border darkens to text.primary while hovered/active.
 *
 * Plain CSSProperties (radius given as an explicit px string, not a bare number) so this drops
 * into both a Box `sx` and a design-system `Button`'s inline `style` without MUI's sx unit
 * multiplier doubling it up. Callers still own height, padding and any layout props specific to
 * their own container (flex-grow, overflow, whiteSpace, ...).
 */
export const filterFieldBoxStyle = (theme: Theme, active: boolean): CSSProperties => ({
  cursor: 'pointer',
  display: 'flex',
  alignItems: 'center',
  width: '100%',
  boxSizing: 'border-box',
  border: `1px solid ${active ? theme.palette.text.primary : theme.palette.divider}`,
  borderRadius: `${theme.shape.borderRadius}px`,
});
