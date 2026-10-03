import type { Theme as MuiTheme } from '@mui/material/styles';
import type { GraphBadgeTone } from '../badges/graphBadgeRegistry';

/**
 * Everything the canvas paints with, resolved from the theme (design-system tokens bridged into
 * the MUI theme): a canvas takes resolved colours, not CSS variables. Entity colours come from
 * the data (`node.color`), never from here.
 */
export interface GraphPalette {
  mode: 'dark' | 'light';
  background: string;
  surface: string;
  text: string;
  textSecondary: string;
  /** Selection, focus and path highlight. */
  accent: string;
  link: string;
  inferred: string;
  disabled: string;
  divider: string;
  tones: Record<GraphBadgeTone, string>;
  /** Opacity of the entity colour laid over the surface inside a node ring. */
  tintAlpha: number;
  /** Opacity of what lies outside the focus. */
  fadeAlpha: number;
}

/**
 * The application theme is created with every palette entry set; its declared type keeps them
 * optional, so the palette is read through the resolved MUI type.
 */
export const buildGraphPalette = (theme: object): GraphPalette => {
  const { palette } = theme as MuiTheme;
  const mode = palette.mode === 'light' ? 'light' : 'dark';
  return {
    mode,
    background: palette.background.default,
    surface: palette.background.paper,
    text: palette.text.primary,
    textSecondary: palette.text.secondary,
    accent: palette.secondary.main,
    link: palette.primary.main,
    inferred: palette.warning.main,
    disabled: palette.background.paper,
    divider: palette.divider,
    tones: {
      neutral: palette.text.secondary,
      info: palette.info.main,
      success: palette.success.main,
      warning: palette.warning.main,
      error: palette.error.main,
      accent: palette.secondary.main,
    },
    tintAlpha: mode === 'dark' ? 0.24 : 0.14,
    fadeAlpha: mode === 'dark' ? 0.16 : 0.22,
  };
};
