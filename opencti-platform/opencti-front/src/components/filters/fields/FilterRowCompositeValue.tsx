import Popover from '@mui/material/Popover';
import { Button } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { Dispatch, FunctionComponent, SetStateAction, useState } from 'react';
import { useFormatter } from '../../i18n';
import { Filter, FilterEditorInputValue } from '../../../utils/filters/filtersHelpers-types';
import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../../utils/fdsLayer';
import FilterValuesForDynamicSubKey from '../FilterValuesForDynamicSubKey';
import FilterValueInput from './FilterValueInput';
import { FILTER_VALUE_POPOVER_MIN_WIDTH } from './filterFieldLayout';

export interface FilterRowCompositeValueProps {
  filter: Filter;
  inputValues: FilterEditorInputValue[];
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
}

/**
 * Read-only value of the 'dynamic' subfilter of a 'dynamicRegardingOf' filter, displayed in the
 * nested-group row (the 'relationship_type' subfilter has its own column next to this one, so it
 * is not shown here). Same 'Dynamic filter' chip + hover tooltip as the root-level filter string
 * (FilterValues / FilterValuesForDynamicSubKey), so the two never drift apart. Clicking it opens a
 * popover with just the nested filter-group editor for that 'dynamic' subfilter.
 */
const FilterRowCompositeValue: FunctionComponent<FilterRowCompositeValueProps> = ({
  filter,
  inputValues,
  setInputValues,
}) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [isHovered, setIsHovered] = useState(false);
  const dynamicValue = filter.values.find((f) => f.key === 'dynamic')?.values?.[0];
  // Opening the popover queries based on the relationship type: without one selected yet, that
  // query has nothing to key off and breaks the app, so the trigger stays disabled until then.
  const hasRelationshipType = filter.values.some((f) => f.key === 'relationship_type');

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
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-start',
          width: '100%',
          height: '100%',
          boxSizing: 'border-box',
          overflow: 'hidden',
          padding: `0 ${theme.spacing(1)}`,
          border: `1px solid ${isHovered && hasRelationshipType ? theme.palette.text.primary : theme.palette.divider}`,
          whiteSpace: 'nowrap',
        }}
      >
        <FilterValuesForDynamicSubKey filterValue={dynamicValue} />
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
          subKey="dynamic"
        />
      </Popover>
    </>
  );
};

export default FilterRowCompositeValue;
