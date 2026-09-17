import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { Checkbox, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { FunctionComponent, HTMLAttributes } from 'react';
import { FILTER_LINE_ITEM_HEIGHT } from '../../../utils/filters/filtersUtils';
import ItemIcon from '../../ItemIcon';

interface FilterEntityOptionProps {
  option: FilterOptionValue;
  checked: boolean;
  /** The last remaining value of a locked filter cannot be unselected. */
  disabled: boolean;
  /** Props MUI injects on the option element, `key` already extracted by the caller. */
  liProps: HTMLAttributes<HTMLLIElement>;
}

/**
 * One row of the entity autocomplete: checkbox, entity icon and truncated label, the whole
 * row also being its own tooltip trigger for the labels the ellipsis cuts.
 */
const FilterEntityOption: FunctionComponent<FilterEntityOptionProps> = ({
  option,
  checked,
  disabled,
  liProps,
}) => {
  const theme = useTheme();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <li
          {...liProps}
          aria-disabled={disabled}
          aria-label={option.label}
          style={{
            whiteSpace: 'nowrap',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            minHeight: FILTER_LINE_ITEM_HEIGHT,
            padding: `0 ${theme.spacing(1)} 0 ${theme.spacing(2)}`,
            gap: theme.spacing(1),
            margin: 0,
            pointerEvents: disabled ? 'none' : undefined,
          }}
        >
          {/* NOT `presentational`, deliberately — see fds-migration/MIGRATION-DECISIONS.md#filter-value-checkbox-role. */}
          <Checkbox checked={checked} disabled={disabled} aria-label={option.label} />
          <ItemIcon type={option.type} color={option.color} />
          <span>
            {option.label}
          </span>
        </li>
      </TooltipTrigger>
      <TooltipContent>{option.label}</TooltipContent>
    </Tooltip>
  );
};

export default FilterEntityOption;
