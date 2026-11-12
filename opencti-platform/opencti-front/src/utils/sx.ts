import { SxProps } from '@mui/material';

/**
 * Merges `sx` values into the array form Material UI accepts; later parts win,
 * so a component passes its own styles first and its caller's `sx` last.
 */
export const mergeSx = <T extends object>(...parts: (SxProps<T> | undefined)[]): SxProps<T> => parts
  .flatMap((part) => (Array.isArray(part) ? part : [part]))
  .filter((part) => part !== undefined);
