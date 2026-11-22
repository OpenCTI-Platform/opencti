import React from 'react';
import Box from '@mui/material/Box';
import type { Theme } from '@mui/material/styles';

// A product mark shipped as a plain single-colour .svg and painted through a CSS mask, so it takes
// the colour of its context (currentColor, the active colour of an emblem, the grey of a muted one)
// without a React component per logo in static/images and without repeated SVG ids.
interface XtmMarkProps {
  src: string;
  size?: number;
  // A colour token or CSS colour, or a { light, dark } pair picked by the theme mode; currentColor by default.
  color?: string | { light: string; dark: string };
}

export const XtmMark: React.FC<XtmMarkProps> = ({ src, size = 20, color = 'currentColor' }) => (
  <Box
    component="span"
    aria-hidden
    data-testid="xtm-mark"
    sx={{
      display: 'inline-block',
      flexShrink: 0,
      width: size,
      height: size,
      bgcolor: typeof color === 'string' ? color : (theme: Theme) => color[theme.palette.mode],
      mask: `url("${src}") center / contain no-repeat`,
      WebkitMask: `url("${src}") center / contain no-repeat`,
    }}
  />
);

export default XtmMark;
