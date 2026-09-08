import AccountTreeOutlined from '@mui/icons-material/AccountTreeOutlined';
import KeyboardArrowDown from '@mui/icons-material/KeyboardArrowDown';
import KeyboardArrowUp from '@mui/icons-material/KeyboardArrowUp';
import Chip from '@mui/material/Chip';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import Stack from '@mui/material/Stack';
import Tooltip from '@mui/material/Tooltip';
import React, { CSSProperties, forwardRef } from 'react';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { useFormatter } from '../../i18n';

export interface FilterGroupChipButtonProps {
  /** The nested group displayed by this chip. */
  filterGroup: FilterGroup;
  /** Whether the associated edition panel is currently displayed. */
  isOpen: boolean;
  /** Called when the user clicks the chip, ignored in read only mode. */
  onClick?: (event: React.MouseEvent<HTMLElement>) => void;
  /** Read only mode: the chip is displayed but not clickable (no helpers, or 'small'/'tag' variants). */
  readOnly?: boolean;
  chipColor?: ChipOwnProps['color'];
  style?: CSSProperties;
}

/**
 * A single chip standing for a nested filter group inside the root filter line: [⛬ 3 rules ▾].
 * The displayed count is the number of DIRECT children of the group (filters + sub-groups).
 * Pure component (no Relay), so it can be unit tested on its own.
 */
const FilterGroupChipButton = forwardRef<HTMLDivElement, FilterGroupChipButtonProps>(({
  filterGroup,
  isOpen,
  onClick,
  readOnly = false,
  chipColor,
  style,
}, ref) => {
  const { t_i18n } = useFormatter();
  const directChildrenCount = filterGroup.filters.length + filterGroup.filterGroups.length;
  const label = `${directChildrenCount} ${t_i18n('rules')}`;
  const isClickable = !readOnly && !!onClick;

  const chip = (
    <Chip
      ref={ref}
      data-testid={`filter-group-chip-${filterGroup.id ?? 'group'}`}
      color={chipColor}
      variant="filled"
      clickable={isClickable}
      onClick={isClickable ? onClick : undefined}
      sx={{
        ...style,
        borderRadius: 1,
        '& .MuiChip-label': {
          lineHeight: '32px',
          display: 'flex',
          alignItems: 'center',
        },
      }}
      label={(
        <Stack direction="row" alignItems="center" gap={0.5}>
          <AccountTreeOutlined fontSize="small" />
          {label}
          {isClickable && (isOpen ? <KeyboardArrowUp fontSize="small" /> : <KeyboardArrowDown fontSize="small" />)}
        </Stack>
      )}
    />
  );

  if (isClickable) return chip;

  return (
    <Tooltip title={t_i18n('This group of filters is displayed in read only mode and cannot be edited here')}>
      <span>{chip}</span>
    </Tooltip>
  );
});

FilterGroupChipButton.displayName = 'FilterGroupChipButton';

export default FilterGroupChipButton;
