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
}

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
  const directChildrenCount = (dynamicValue?.filters?.length ?? 0) + (dynamicValue?.filterGroups?.length ?? 0);
  const dynamicValueLabel = directChildrenCount === 0
    ? t_i18n('Add dynamic filter')
    : `${directChildrenCount} ${directChildrenCount === 1 ? t_i18n('dynamic filter rule') : t_i18n('dynamic filter rules')}`;
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
          subKey="dynamic"
        />
      </Popover>
    </>
  );
};

export default FilterRowCompositeValue;
