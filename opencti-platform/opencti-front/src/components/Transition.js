import React from 'react';
import Slide from '@mui/material/Slide';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

export default Transition;
