import React, { CSSProperties, FunctionComponent } from 'react';
import { useFormatter } from './i18n';
import { Box } from '@mui/material';
import { useTheme } from '@mui/material/styles';

interface FilterIconButtonGlobalModeProps {
  operatorStyle: CSSProperties;
  globalMode: string;
  handleSwitchGlobalMode?: () => void;
  isOperatorClickable: boolean;
}
const FilterIconButtonGlobalMode: FunctionComponent<
  FilterIconButtonGlobalModeProps
> = ({
  operatorStyle,
  globalMode,
  handleSwitchGlobalMode,
  isOperatorClickable,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const clickableOperatorOnHoverStyle = {
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: `${theme.palette.action?.disabled} !important`,
      textDecorationLine: 'underline',
    },
  };

  return (
    <Box
      style={operatorStyle}
      sx={isOperatorClickable ? clickableOperatorOnHoverStyle : undefined}
      onClick={handleSwitchGlobalMode}
    >
      {t_i18n(globalMode.toLowerCase())}
    </Box>
  );
};

export default FilterIconButtonGlobalMode;
