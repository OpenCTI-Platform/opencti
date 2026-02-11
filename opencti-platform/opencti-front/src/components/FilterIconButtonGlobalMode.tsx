import React, { FunctionComponent } from 'react';
import { useFormatter } from './i18n';
import { Box } from '@mui/material';

interface FilterIconButtonGlobalModeProps {
  classOperator: string;
  globalMode: string;
  handleSwitchGlobalMode?: () => void;
}
const FilterIconButtonGlobalMode: FunctionComponent<
  FilterIconButtonGlobalModeProps
> = ({
  classOperator,
  globalMode,
  handleSwitchGlobalMode,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Box className={classOperator} onClick={handleSwitchGlobalMode}>
      {t_i18n(globalMode.toLowerCase())}
    </Box>
  );
};

export default FilterIconButtonGlobalMode;
