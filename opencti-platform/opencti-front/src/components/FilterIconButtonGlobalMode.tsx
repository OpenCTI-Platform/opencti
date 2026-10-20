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
  const label = t_i18n(globalMode.toLowerCase());

  if (!isOperatorClickable || !handleSwitchGlobalMode) {
    return <Box style={operatorStyle}>{label}</Box>;
  }

  return (
    // FDS-WORKAROUND #67: bare <button>, the library Button and IconButton always paint a box — see fds-migration/LIBRARY-FEEDBACK.md #67
    <Box
      component="button"
      type="button"
      style={operatorStyle}
      sx={{
        border: 'none',
        font: 'inherit',
        lineHeight: 'inherit',
        color: 'inherit',
        cursor: 'pointer',
        '&:hover': {
          backgroundColor: `${theme.palette.action?.disabled} !important`,
          textDecorationLine: 'underline',
        },
      }}
      onClick={handleSwitchGlobalMode}
    >
      {label}
    </Box>
  );
};

export default FilterIconButtonGlobalMode;
