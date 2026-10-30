import { styled } from '@mui/material/styles';
import type { ComponentType, InputHTMLAttributes, RefAttributes } from 'react';

// The type `styled('input')` infers reaches a nested copy of `@mui/system` under
// `@mui/material`, which no import specifier can name, so it has to be declared.
// Every call site uses this as a plain file input, which is what it is declared as.
const VisuallyHiddenInput: ComponentType<
InputHTMLAttributes<HTMLInputElement> & RefAttributes<HTMLInputElement>
> = styled('input')`
  clip: rect(0 0 0 0);
  clip-path: inset(50%);
  height: 1rem;
  overflow: hidden;
  position: absolute;
  bottom: 0;
  left: 0;
  white-space: nowrap;
  width: 1rem;
`;

export default VisuallyHiddenInput;
