import { useEffect } from 'react';
import { isLightThemeName } from '../themeName';
import { FDS } from '../../components/fds-tokens.generated';

export type FdsThemeMode = 'light' | 'dark';

export interface FdsCustomTheme {
  background?: string | null;
  paper?: string | null;
  nav?: string | null;
  primary?: string | null;
  secondary?: string | null;
  accent?: string | null;
  text?: string | null;
}

/**
 * Single writer of the `.light` / `.dark` class FDS components read, on the document
 * ROOT because FDS portals its floating layers into `<body>`. See
 * fds-migration/MIGRATION-DECISIONS.md#theme-scope-root
 *
 * MUI's palette does not drive CSS custom properties, so a colour not written here
 * keeps the library's own value.
 */

/** One setting, one token. The defaults these override live in ThemeDark/ThemeLight. */
const DIRECT_TOKENS = {
  background: '--bg-elevation-default-layer-0',
  paper: '--bg-elevation-default-layer-1',
  accent: '--bg-elevation-default-layer-3',
  nav: '--bg-elevation-heading-layer-0',
  primary: '--color-filigran-brand-primary',
  secondary: '--color-filigran-tonic-primary',
  text: '--text-default-primary',
} as const satisfies Record<keyof FdsCustomTheme, string>;

/**
 * A layer is a family: the surface plus the fields and borders painted on it. Only
 * the surface has a setting, so the rest is moved by the step the library itself
 * puts between them — read, not hardcoded, because its sign flips between modes and
 * between layers.
 */
const LAYER_FAMILY = [
  'bg-elevation-highlight',
  'bg-elevation-hover',
  'bg-elevation-heading',
  'bg-elevation-disabled',
  'border-elevation-subtle',
  'border-elevation-subtle-soft',
  'border-elevation-default',
  'border-elevation-disabled',
] as const;

const SURFACE_BY_SETTING = {
  background: 0,
  paper: 1,
  accent: 3,
} as const;

/** Layer 2 carries the drawers and has no setting; it follows `paper`. */
const DERIVED_SURFACE_LAYER = 2;
const DERIVED_SURFACE_FROM: keyof FdsCustomTheme = 'paper';

/**
 * The library's own step is faint at layer 2, where dialogs live, so a field could
 * vanish into its modal. The floor is the library's best step, not an invented one.
 */
const highlightFloor = (mode: FdsThemeMode): number => {
  const palette = FDS.colors[mode] as Record<string, string>;
  let best = 0;
  for (let layer = 0; layer <= 3; layer += 1) {
    const surface = toHsl(palette[`--bg-elevation-default-layer-${layer}`] ?? '');
    const field = toHsl(palette[`--bg-elevation-highlight-layer-${layer}`] ?? '');
    if (surface && field) best = Math.max(best, Math.abs(field[2] - surface[2]));
  }
  return best;
};

/** The body gradient's far stop: a token of its own, not a layer member. */
const GRADIENT_STOP = '--bg-elevation-default-layer-0-gradient';

/** Secondary and disabled text, moved by the library's own step from primary. */
const TEXT_FAMILY = ['--text-default-secondary', '--text-default-disabled'] as const;

/** A brand colour is a family too: a primary button paints its TERTIARY on hover. */
const ACCENT_FAMILIES = [
  { setting: 'primary' as const, root: '--color-filigran-brand-primary',
    members: ['--color-filigran-brand-secondary', '--color-filigran-brand-tertiary'] },
  { setting: 'secondary' as const, root: '--color-filigran-tonic-primary',
    members: ['--color-filigran-tonic-secondary', '--color-filigran-tonic-tertiary',
      '--color-filigran-tonic-accent'] },
];

const toHsl = (hex: string): [number, number, number] | null => {
  const m = /^#?([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i.exec(hex.trim());
  if (!m) return null;
  const [r, g, b] = m.slice(1).map((c) => parseInt(c, 16) / 255);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  const d = max - min;
  if (d === 0) return [0, 0, l];
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  let h;
  if (max === r) h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
  else if (max === g) h = ((b - r) / d + 2) / 6;
  else h = ((r - g) / d + 4) / 6;
  return [h, s, l];
};

const fromHsl = ([h, s, l]: [number, number, number]): string => {
  const f = (n: number) => {
    const k = (n + h * 12) % 12;
    const a = s * Math.min(l, 1 - l);
    const v = l - a * Math.max(-1, Math.min(k - 3, 9 - k, 1));
    return Math.round(Math.max(0, Math.min(1, v)) * 255)
      .toString(16)
      .padStart(2, '0');
  };
  return `#${f(0)}${f(8)}${f(4)}`;
};

/**
 * `custom` moved by the step the library puts between `from` and `to`, mirrored
 * rather than clamped when there is no room left.
 */
const movedBy = (
  custom: string,
  from: string,
  to: string,
  mode: FdsThemeMode,
  floor = 0,
): string | null => {
  const palette = FDS.colors[mode] as Record<string, string>;
  const base = toHsl(palette[from] ?? '');
  const target = toHsl(palette[to] ?? '');
  const source = toHsl(custom);
  if (!base || !target || !source) return null;
  const raw = target[2] - base[2];
  const step = Math.abs(raw) >= floor ? raw : Math.sign(raw || 1) * floor;
  const room = step >= 0 ? 1 - source[2] : source[2];
  const applied = Math.abs(step) <= room ? step : -step;
  return fromHsl([source[0], source[1], Math.max(0, Math.min(1, source[2] + applied))]);
};

const useFdsThemeScope = (
  themeName: string | undefined,
  custom: FdsCustomTheme = {},
): FdsThemeMode => {
  const mode: FdsThemeMode = isLightThemeName(themeName) ? 'light' : 'dark';
  const { background, paper, nav, primary, secondary, accent, text } = custom;

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', mode === 'dark');
    root.classList.toggle('light', mode === 'light');
  }, [mode]);

  useEffect(() => {
    const root = document.documentElement;
    const resolved: FdsCustomTheme = { background, paper, nav, primary, secondary, accent, text };

    const palette = FDS.colors[mode] as Record<string, string>;

    const set = (token: string, value: string | null | undefined) => {
      if (value) root.style.setProperty(token, value);
      else root.style.removeProperty(token);
    };

    // Writing a value equal to the library's would freeze the default theme on it.
    const customised = (setting: keyof FdsCustomTheme): string | null => {
      const value = resolved[setting];
      if (!value) return null;
      return value.toLowerCase() === palette[DIRECT_TOKENS[setting]]?.toLowerCase() ? null : value;
    };

    const surfaces = new Map<number, string | null>();
    (Object.keys(SURFACE_BY_SETTING) as (keyof typeof SURFACE_BY_SETTING)[]).forEach((setting) => {
      surfaces.set(SURFACE_BY_SETTING[setting], customised(setting));
    });
    const paperSurface = customised(DERIVED_SURFACE_FROM);
    const derivedSurface = paperSurface
      ? movedBy(
          paperSurface,
          `--bg-elevation-default-layer-${SURFACE_BY_SETTING[DERIVED_SURFACE_FROM]}`,
          `--bg-elevation-default-layer-${DERIVED_SURFACE_LAYER}`,
          mode,
        )
      : null;
    set(`--bg-elevation-default-layer-${DERIVED_SURFACE_LAYER}`, derivedSurface);
    surfaces.set(DERIVED_SURFACE_LAYER, derivedSurface);

    surfaces.forEach((surface, layer) => {
      LAYER_FAMILY.forEach((family) => {
        set(
          `--${family}-layer-${layer}`,
          surface
            ? movedBy(
                surface,
                `--bg-elevation-default-layer-${layer}`,
                `--${family}-layer-${layer}`,
                mode,
                family === 'bg-elevation-highlight' ? highlightFloor(mode) : 0,
              )
            : null,
        );
      });
    });

    // Last: `nav` owns --bg-elevation-heading-layer-0 outright, it is not derived.
    (Object.keys(DIRECT_TOKENS) as (keyof FdsCustomTheme)[]).forEach((setting) => {
      set(DIRECT_TOKENS[setting], customised(setting));
    });

    const primaryText = customised('text');
    TEXT_FAMILY.forEach((token) => {
      set(token, primaryText ? movedBy(primaryText, '--text-default-primary', token, mode) : null);
    });

    const pageSurface = customised('background');
    set(GRADIENT_STOP, pageSurface
      ? movedBy(pageSurface, '--bg-elevation-default-layer-0', GRADIENT_STOP, mode)
      : null);

    ACCENT_FAMILIES.forEach(({ setting, root: rootToken, members }) => {
      const chosen = customised(setting);
      members.forEach((token) => {
        set(token, chosen ? movedBy(chosen, rootToken, token, mode) : null);
      });
    });
  }, [background, paper, nav, primary, secondary, accent, text, mode]);

  return mode;
};

export default useFdsThemeScope;
