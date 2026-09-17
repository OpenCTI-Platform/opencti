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

/** Floating value editor of a composite filter: narrower than this, the entity picker wraps. */
export const FILTER_VALUE_POPOVER_MIN_WIDTH = 250;
