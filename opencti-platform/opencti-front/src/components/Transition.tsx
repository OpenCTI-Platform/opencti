import React, { JSXElementConstructor } from 'react';
import { Slide } from '@mui/material';
import { TransitionProps } from '@mui/material/transitions';

const Transition = React.forwardRef(
  (
    {
      children,
      ...props
    }: TransitionProps & {
      children: React.ReactElement<
      unknown,
      string | JSXElementConstructor<unknown>
      >;
    },
    ref: React.Ref<unknown>,
  ) => {
    return (
      <Slide direction="up" ref={ref} {...props}>
        {children}
      </Slide>
    );
  },
);
Transition.displayName = 'TransitionSlide';

export default Transition;
