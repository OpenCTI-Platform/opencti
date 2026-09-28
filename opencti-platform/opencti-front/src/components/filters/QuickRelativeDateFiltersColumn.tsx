import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/material/styles';
import QuickRelativeDateFiltersButtons from './QuickRelativeDateFiltersButtons';
import { Filter, handleFilterHelpers } from '../../utils/filters/filtersHelpers-types';

interface QuickRelativeDateFiltersColumnProps {
  filter?: Filter;
  helpers?: handleFilterHelpers;
  handleClose: () => void;
}

/**
 * The vertical divider + quick relative-date shortcuts column, standing to the right of a
 * `within` date filter's editor. Top-aligned with whatever it's placed beside — the caller
 * decides what that is: the whole operator+fields column in the root chip popover, or just the
 * fields in the nested-group row's dedicated popover (`DateRangeFilterFields`).
 */
const QuickRelativeDateFiltersColumn: FunctionComponent<QuickRelativeDateFiltersColumnProps> = ({
  filter,
  helpers,
  handleClose,
}) => {
  const theme = useTheme();

  return (
    <div style={{ display: 'inline-flex', flexShrink: 0, width: 'max-content' }}>
      <div style={{
        color: theme.palette.text.disabled,
        borderLeft: '0.5px solid',
        marginLeft: '10px',
        alignSelf: 'stretch',
      }}
      />
      <QuickRelativeDateFiltersButtons filter={filter} helpers={helpers} handleClose={handleClose} />
    </div>
  );
};

export default QuickRelativeDateFiltersColumn;
