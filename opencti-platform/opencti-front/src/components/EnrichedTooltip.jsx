import React from 'react';
import Tooltip, { tooltipClasses } from '@mui/material/Tooltip';
import { styled } from '@mui/material/styles';

const EnrichedTooltip = styled(({ className, ...props }) => (
  <Tooltip {...props} classes={{ popper: className }} />
))(({ theme }) => ({
  [`& .${tooltipClasses.tooltip}`]: {
    width: 400,
    padding: '20px 20px 10px 20px',
    backgroundColor: theme.palette.mode === 'light'
      ? theme.palette.common.white
      : theme.palette.common.black,
    boxShadow: theme.shadows[1],
  },
  [`& .${tooltipClasses.popper}`]: {},
}));

export default EnrichedTooltip;
