import type { CreateCSSProperties } from '@mui/styles/withStyles';

/**
 * The cell of a legacy list line (`ListLines` + its `*Line` components).
 *
 * This shape was copy-pasted, byte for byte, into 50 line components, with a
 * further 20-odd near-variants beside them. That is why "the text is not
 * centred in the cell" reads as a defect of every table at once: it is one
 * style, duplicated. It lives here now so the next correction is one edit.
 *
 * The centring is `display: flex` + `align-items: center` and NOT the removal
 * of `float`. The cells are plain `<div>`s inside `ListItemText`, with no flex
 * parent -- the float is the only thing making them sit side by side, so
 * dropping it would stack every column vertically. A floated box can still be a
 * flex container, which is what two line components in this repo already ship
 * (`WorkbenchFileContent` and its neighbour), so this is the in-repo shape
 * rather than a new invention.
 *
 * `minWidth: 0` is there so the ellipsis still resolves once the cell is a flex
 * container: a flex item's default `min-width: auto` refuses to shrink below
 * its content, which is what would silently defeat `text-overflow`.
 */
export const bodyItemStyle: CreateCSSProperties = {
  height: 25,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
  display: 'flex',
  alignItems: 'center',
  minWidth: 0,
};
