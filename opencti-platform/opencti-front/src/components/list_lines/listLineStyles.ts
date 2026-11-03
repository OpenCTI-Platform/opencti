import type { CSSObject } from '@mui/material/styles';

export const bodyItemStyle: CSSObject = {
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
  // `textOverflow` above only reaches text directly in the cell, never a child
  // element such as a chip.
  '& > *': {
    maxWidth: '100%',
    minWidth: 0,
  },
};
