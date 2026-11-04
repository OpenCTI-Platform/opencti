import Box from '@mui/material/Box';
import { useTheme } from '@mui/material/styles';
import { FunctionComponent } from 'react';
import { FILTER_LINE_ITEM_HEIGHT } from '../../../utils/filters/filtersUtils';
import FilterIconButtonGlobalMode from '../../FilterIconButtonGlobalMode';
import { getChipStyles } from '../filterChipStyles';

/** The and/or of a group as in the root filter line, for a display with nothing to edit. */
const GroupModeChip: FunctionComponent<{ mode: string }> = ({ mode }) => {
  const theme = useTheme();
  const { operatorStyle } = getChipStyles(theme);
  return (
    <Box sx={{ display: 'flex' }}>
      <FilterIconButtonGlobalMode
        operatorStyle={{ ...operatorStyle, height: FILTER_LINE_ITEM_HEIGHT }}
        globalMode={mode}
        isOperatorClickable={false}
      />
    </Box>
  );
};

export default GroupModeChip;
