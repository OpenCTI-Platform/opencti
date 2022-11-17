/* eslint-disable  @typescript-eslint/no-explicit-any */
import React from 'react';
import Slide from '@mui/material/Slide';
import { TransitionProps } from '@mui/material/transitions';

const Transition = React.forwardRef((
  { children, ...props }: TransitionProps & {
    children: React.ReactElement<any, any>;
  },
  ref: React.Ref<unknown>,
) => {
  return <Slide direction="up" ref={ref} {...props}>{children}</Slide>;
});
Transition.displayName = 'TransitionSlide';

export default Transition;
