import React, { FunctionComponent, useState } from 'react';
import Popover from '@mui/material/Popover';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import DateRangeFields from './DateRangeFields';
import DateRangeFilterFields from './DateRangeFilterFields';
import { useFormatter } from '../i18n';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';
import { isDateIntervalTranslatable, isValidDate, translateDateInterval } from '../../utils/String';
import { FILTER_POPOVER_LAYER, fdsLayerClass, filterPopoverPaperSx } from '../../utils/fdsLayer';
import { filterFieldBoxStyle } from './fields/filterFieldLayout';

interface DateRangeFilterProps {
  filter?: Filter;
  filterKey: string;
  helpers?: handleFilterHelpers;
  filterValues: string[];
  /**
   * Compact textual summary that opens a dedicated popover instead of the fields shown inline —
   * the nested-group row layout, which has no room for the full editor. The root chip popover
   * (already a popover) shows the fields inline instead, and gets its own shortcuts column from
   * `FilterChipPopover` directly (top-aligned with the operator select, not just the fields).
   */
  showRelativeDateShortcuts?: boolean;
}

const DateRangeFilter: FunctionComponent<DateRangeFilterProps> = ({
  filter,
  filterKey,
  filterValues,
  helpers,
  showRelativeDateShortcuts = false,
}) => {
  const { t_i18n, smhd } = useFormatter();
  const theme = useTheme();
  const [dateInput, setDateInput] = useState(filterValues);
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);

  if (!showRelativeDateShortcuts) {
    return (
      <DateRangeFields
        filter={filter}
        filterKey={filterKey}
        helpers={helpers}
        dateInput={dateInput}
        setDateInput={setDateInput}
      />
    );
  }

  const formatValue = (value: string) => (isValidDate(value) ? smhd(value) : value);
  const summary = isDateIntervalTranslatable(filterValues)
    ? translateDateInterval(filterValues, t_i18n)
    : `${formatValue(filterValues[0])} — ${formatValue(filterValues[1])}`;

  return (
    <>
      <Box
        component="span"
        onClick={(event) => setAnchorEl(event.currentTarget)}
        sx={{
          ...filterFieldBoxStyle(theme, false),
          height: 40,
          padding: '0 14px',
          '&:hover': filterFieldBoxStyle(theme, true),
        }}
      >
        {summary}
      </Box>
      <Popover
        open={!!anchorEl}
        anchorEl={anchorEl}
        onClose={() => setAnchorEl(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
        slotProps={{
          paper: {
            elevation: 1,
            className: fdsLayerClass(FILTER_POPOVER_LAYER),
            sx: { ...filterPopoverPaperSx, marginTop: '10px' },
          },
        }}
      >
        <DateRangeFilterFields
          filter={filter}
          filterKey={filterKey}
          helpers={helpers}
          dateInput={dateInput}
          setDateInput={setDateInput}
          handleClose={() => setAnchorEl(null)}
        />
      </Popover>
    </>
  );
};

export default DateRangeFilter;
