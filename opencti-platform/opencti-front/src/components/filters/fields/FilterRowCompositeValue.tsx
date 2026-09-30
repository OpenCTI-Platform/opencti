import Popover from '@mui/material/Popover';
import { Button } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { Dispatch, FunctionComponent, SetStateAction, useState } from 'react';
import { useFormatter } from '../../i18n';
import { Filter, FilterEditorInputValue } from '../../../utils/filters/filtersHelpers-types';
import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../../utils/fdsLayer';
import FilterValueInput from './FilterValueInput';
import { FILTER_VALUE_POPOVER_MIN_WIDTH, filterFieldBoxStyle } from './filterFieldLayout';

export interface FilterRowCompositeValueProps {
  filter: Filter;
  inputValues: FilterEditorInputValue[];
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
  /**
   * Sub-key holding the nested filter group, for a composite filter ('dynamicRegardingOf''s
   * 'dynamic' subfilter — the only composite that reaches this component). Omit for a filter
   * whose value IS directly the nested group ('dynamicFrom'/'dynamicTo') — then there is no
   * relationship-type gating either.
   */
  subKey?: 'dynamic';
}

/**
 * Read-only value of a filter's nested filter-group value, displayed in the nested-group row:
 * either the 'dynamic' subfilter of a composite 'dynamicRegardingOf' filter (the 'relationship_type'
 * subfilter has its own column next to this one, so it is not shown here — pass `subKey="dynamic"`),
 * or the whole value of a standalone 'dynamicFrom'/'dynamicTo' filter (omit `subKey`, no relationship
 * type involved). Unlike the root-level filter string (FilterValues), which shows a 'Dynamic filter'
 * chip regardless of content, this compact row has room only for a rule count: 'Add value' while the
 * nested group is empty, '<n> dynamic filter rule(s)' once it has direct children (filters +
 * sub-groups — same counting as FilterGroupChipButton). Clicking it opens a popover with just the
 * nested filter-group editor.
 */
const FilterRowCompositeValue: FunctionComponent<FilterRowCompositeValueProps> = ({
  filter,
  inputValues,
  setInputValues,
  subKey,
}) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [isHovered, setIsHovered] = useState(false);
  const dynamicValue = subKey ? filter.values.find((f) => f.key === subKey)?.values?.[0] : filter.values[0];
  const directChildrenCount = (dynamicValue?.filters?.length ?? 0) + (dynamicValue?.filterGroups?.length ?? 0);
  const dynamicValueLabel = directChildrenCount === 0
    ? t_i18n('Add dynamic filter')
    : `${directChildrenCount} ${directChildrenCount === 1 ? t_i18n('dynamic filter rule') : t_i18n('dynamic filter rules')}`;
  const hasRelationshipType = !subKey || filter.values.some((f) => f.key === 'relationship_type');

  return (
    <>
      <Button
        data-testid={`filter-row-composite-value-${filter.id}`}
        aria-label={t_i18n('Edit dynamic filter')}
        onClick={(event) => setAnchorEl(event.currentTarget)}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        disabled={!hasRelationshipType}
        variant="default"
        priority="tertiary"
        size="sm"
        className="!rounded-sm !bg-transparent !font-normal !normal-case"
        style={{
          ...filterFieldBoxStyle(theme, isHovered && hasRelationshipType),
          justifyContent: 'flex-start',
          height: '100%',
          overflow: 'hidden',
          padding: `0 ${theme.spacing(1)}`,
          whiteSpace: 'nowrap',
        }}
      >
        {dynamicValueLabel}
      </Button>
      <Popover
        open={!!anchorEl}
        anchorEl={anchorEl}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        slotProps={{
          paper: {
            elevation: 1,
            className: fdsLayerClass(FILTER_POPOVER_LAYER),
            sx: { ...filterPopoverPaperSx, marginTop: theme.spacing(1.25), minWidth: FILTER_VALUE_POPOVER_MIN_WIDTH, padding: 1 },
          },
        }}
      >
        <FilterValueInput
          filter={filter}
          filterKey={filter.key}
          inputValues={inputValues}
          setInputValues={setInputValues}
          subKey={subKey}
        />
      </Popover>
    </>
  );
};

export default FilterRowCompositeValue;
