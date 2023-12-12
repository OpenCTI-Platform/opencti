import React, { FunctionComponent } from 'react';
import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from './i18n';
import { Filter, filtersUsedAsApiParameters } from '../utils/filters/filtersUtils';

interface FilterIconButtonGlobalOperatorProps {
  classOperator: string;
  globalMode: string;
  displayedFilters: Filter[];
  currentIndex: number;
  handleSwitchGlobalMode?: () => void;
}
const FilterIconButtonGlobalOperator: FunctionComponent<
FilterIconButtonGlobalOperatorProps
> = ({
  classOperator,
  globalMode,
  displayedFilters,
  currentIndex,
  handleSwitchGlobalMode,
}) => {
  const { t } = useFormatter();
  const theme = useTheme();
  if (filtersUsedAsApiParameters.includes(displayedFilters[currentIndex].key)) {
    return (
      <Box
        sx={{
          borderRadius: '5px',
          fontFamily: 'Consolas, monaco, monospace',
          backgroundColor: theme?.palette.action?.selected,
          padding: '0 8px',
          display: 'flex',
          alignItems: 'center',
        }}
      >
        {t('AND')}
      </Box>
    );
  }

  return (
    <div className={classOperator} onClick={handleSwitchGlobalMode}>
      {t(globalMode.toUpperCase())}
    </div>
  );
};

export default FilterIconButtonGlobalOperator;
