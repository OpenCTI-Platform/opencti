import type { CSSProperties } from 'react';
import type { Theme } from '@mui/material/styles';
import { FILTER_LINE_ITEM_HEIGHT } from '../../utils/filters/filtersUtils';
import type { FilterIconButtonVariant } from '../FilterIconButtonContainer';

/** Geometry of a filter chip and of its operator badge, per display variant. */
export const getChipStyles = (theme: Theme, variant?: FilterIconButtonVariant) => {
  const operatorStyle: CSSProperties = {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
  };
  if (variant === 'small') {
    return {
      filterStyle: {
        fontSize: 12,
        height: 20,
        borderRadius: 4,
        lineHeight: `${FILTER_LINE_ITEM_HEIGHT}px`,
      } as CSSProperties,
      operatorStyle: {
        borderRadius: 4,
        fontFamily: 'Consolas, monaco, monospace',
        backgroundColor: theme.palette.action?.selected,
        padding: '0 8px',
        height: 20,
        marginRight: 5,
        marginLeft: 5,
      } as CSSProperties,
    };
  }
  if (variant === 'tag') {
    return { filterStyle: { height: 25 } as CSSProperties, operatorStyle };
  }
  return { filterStyle: undefined as CSSProperties | undefined, operatorStyle };
};
