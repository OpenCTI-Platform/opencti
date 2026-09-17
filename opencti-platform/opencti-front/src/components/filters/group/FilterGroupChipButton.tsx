import FilterListOutlinedIcon from '@mui/icons-material/FilterListOutlined';
import KeyboardArrowDown from '@mui/icons-material/KeyboardArrowDown';
import KeyboardArrowUp from '@mui/icons-material/KeyboardArrowUp';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { useTheme } from '@mui/material/styles';
import React, { CSSProperties, forwardRef } from 'react';
import Button from '@common/button/Button';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { FILTER_LINE_ITEM_HEIGHT } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../i18n';

export interface FilterGroupChipButtonProps {
  /** The nested group displayed by this chip. */
  filterGroup: FilterGroup;
  /** Whether the associated edition panel is currently displayed. */
  isOpen: boolean;
  /** Called when the user clicks the chip, ignored in read only mode. */
  onClick: (event: React.MouseEvent<HTMLElement>) => void;
  /** Kept for API compatibility with the parent filter line; the plain button no longer varies by color. */
  chipColor?: ChipOwnProps['color'];
  style?: CSSProperties;
}

/**
 * A single button standing for a nested filter group inside the root filter line: [⛬ 3 rules ▾].
 * The displayed count is the number of DIRECT children of the group (filters + sub-groups).
 * Pure component (no Relay), so it can be unit tested on its own.
 */
const FilterGroupChipButton = forwardRef<HTMLSpanElement, FilterGroupChipButtonProps>(({
  filterGroup,
  isOpen,
  onClick,
  style,
}, ref) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const directChildrenCount = filterGroup.filters.length + filterGroup.filterGroups.length;
  const label = `${directChildrenCount} ${directChildrenCount === 1 ? t_i18n('rule') : t_i18n('rules')}`;

  // The wrapping `span` carries the ref (button-in-a-box) and is the actual click target:
  // `Button` is a plain function component (no forwardRef), so a ref placed on it would be
  // silently dropped, breaking the click-away containment check done by the parent filter line.
  return (
    <span
      ref={ref}
      data-testid={`filter-group-chip-${filterGroup.id ?? 'group'}`}
      style={style}
      onClick={onClick}
    >
      <Button
        variant="secondary"
        startIcon={<FilterListOutlinedIcon fontSize="small" color="primary" />}
        endIcon={isOpen ? <KeyboardArrowUp fontSize="small" /> : <KeyboardArrowDown fontSize="small" />}
        style={{ color: theme.palette.text.primary, height: FILTER_LINE_ITEM_HEIGHT, ...style }}
      >
        {label}
      </Button>
    </span>
  );
});

FilterGroupChipButton.displayName = 'FilterGroupChipButton';

export default FilterGroupChipButton;
