import type { CreateCSSProperties } from '@mui/styles/withStyles';

/**
 * The cell of a legacy list line (`ListLines` + its `*Line` components).
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
