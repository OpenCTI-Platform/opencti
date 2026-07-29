import React, { useMemo, useRef, useState } from 'react';
import { StyledEngineProvider, ThemeProvider, createTheme } from '@mui/material/styles';
import type { ThemeOptions } from '@mui/material/styles/createTheme';
import CssBaseline from '@mui/material/CssBaseline';
import GlobalStyles from '@mui/material/GlobalStyles';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { Navbar, NavbarItem, NavbarSeparator, NavbarSubmenu, NavbarSubmenuItem, ProductSwitcher, Icon } from '@filigran/design-system';
// Pre-built, self-contained stylesheet (tokens + Tailwind utilities used by
// the library's own components). No preflight/reset included, so this is
// safe to load alongside MUI's baseline (see the package's tokens/index.css
// source comment: "A distributed component library must never impose a
// global CSS reset. Host apps ... include their own preflight.").
import '@filigran/design-system/dist/index.css';
import ThemeDark from '../components/ThemeDark';
import ThemeLight from '../components/ThemeLight';
import useFdsThemeScope from '../utils/hooks/useFdsThemeScope';

/**
 * ============================================================================
 * TEMPORARY SPIKE — NOT PRODUCTION CODE — SAFE TO DELETE AFTER REVIEW.
 * ============================================================================
 *
 * Purpose: an isolated, throwaway visual test of the @filigran/design-system
 * `Navbar` / `NavbarItem` / `NavbarSubmenu` / `ProductSwitcher` components
 * rendered inside OpenCTI's real build/toolchain (Vite, MUI theme tokens),
 * using only fake/representative data — no GraphQL/API integration.
 *
 * This is deliberately NOT wired into the real navigation:
 *  - LeftBar.jsx / LeftBarItem.tsx (production nav) are untouched.
 *  - This screen is only reachable by directly visiting its own route
 *    (see `app.tsx`); it is not linked from any menu.
 *  - `useFdsThemeScope` is used exactly as documented in its own file
 *    (imported and called here, with a local `containerRef`) — the hook
 *    itself is untouched, as are ThemeDark.ts/ThemeLight.ts/
 *    AppThemeProvider.tsx/fds-tokens.generated.ts (consumed only).
 *
 * ⚠ ProductSwitcher color caveat (see ProductSwitcher.rfc.md in the
 * filigran-design-system repo): every color token on ProductSwitcher is
 * REUSED from NavbarItem/NavbarSubmenuItem, flagged "to revalidate" rather
 * than final — there is no dedicated Figma symbol for this component yet.
 * Do not treat the colors rendered below as a reliable reference.
 *
 * ⚠ Finding surfaced by this spike (not fixed here — lives in
 * filigran-design-system, not opencti): toggling light/dark via
 * `useFdsThemeScope` correctly re-themes solid-color tokens (text, icons,
 * borders), but `Navbar`'s own background — `bg-gradient-default`
 * (Navbar.tsx) — stays frozen on its dark-mode gradient in light mode too.
 * Root cause appears to be that `--gradient-default` (theme.css) embeds
 * nested `var()` references that don't re-resolve against the `.light`/
 * `.dark` overrides of their sub-tokens the way plain solid tokens do.
 * Navbar.rfc.md §"cross-component inconsistency" still describes the
 * older flat-color implementation and says light/dark is mode-agnostic;
 * the component was since changed to this gradient (see fidelity re-pass
 * comments in Navbar.tsx), so that RFC note is stale. Not resolved here —
 * flagged for the design-system team.
 */

const FAKE_USER_NAME = 'Jane Doe (Analyst)';

const fakeProductOptions = [
  {
    id: 'openaev',
    label: 'OpenAEV',
    logo: <Icon name="custom/openaev" size={20} />,
    tooltip: 'Breach and attack simulation platform (fake link — spike only)',
    href: 'https://openaev.example.invalid',
  },
  {
    id: 'opengrc',
    label: 'OpenGRC',
    logo: <Icon name="custom/opengrc" size={20} />,
    tooltip: 'Governance, risk and compliance platform (fake link — spike only)',
    href: 'https://opengrc.example.invalid',
  },
  {
    id: 'xtmhub',
    label: 'XTM Hub',
    logo: <Icon name="custom/xtmhub" size={20} />,
    tooltip: 'Central hub for connectors and integrations (fake link — spike only)',
    href: 'https://xtmhub.example.invalid',
  },
];

const preventDefault = (e: React.MouseEvent) => e.preventDefault();

interface SpikeContentProps {
  mode: 'dark' | 'light';
  onToggleMode: () => void;
}

/**
 * Rendered as a child of the local `ThemeProvider` below so that
 * `useFdsThemeScope` (which reads `theme.palette.mode` via `useTheme`) sees
 * the right MUI theme context — mirrors the pattern already validated in
 * `useFdsThemeScope.test.tsx`.
 */
const SpikeContent = ({ mode, onToggleMode }: SpikeContentProps) => {
  const containerRef = useRef<HTMLDivElement>(null);
  // Bridges theme.palette.mode -> .dark/.light classes on containerRef, so
  // FDS components' CSS custom properties resolve to the right mode. Used
  // as-is, per the hook's own docstring instructions.
  useFdsThemeScope(containerRef);

  return (
    <Box sx={{ display: 'flex', height: '100vh', width: '100%', bgcolor: 'background.default' }}>
      {/* dist/index.css intentionally ships without Tailwind preflight (see
          import comment above), so native <button> elements keep the
          browser's default appearance/background unless the host resets
          them. This mirrors Tailwind preflight's own button rule, scoped to
          this spike's container only — never applied globally. */}
      <GlobalStyles
        styles={{
          '.fds-spike-scope button': {
            appearance: 'none',
            WebkitAppearance: 'none',
            backgroundColor: 'transparent',
            backgroundImage: 'none',
          },
        }}
      />
      <Box
        ref={containerRef}
        className="fds-spike-scope"
        sx={{ height: '100%', flexShrink: 0 }}
      >
        <Navbar
          aria-label="FDS spike navigation"
          header={(
            <ProductSwitcher
              label="Switch product"
              logo={<Icon name="custom/opencti" size={20} />}
              options={fakeProductOptions}
            />
          )}
          footer={(
            <NavbarItem icon={<Icon name="user" size={16} />} onClick={preventDefault}>
              {FAKE_USER_NAME}
            </NavbarItem>
          )}
        >
          <NavbarItem
            icon={<Icon name="layout-dashboard" size={16} />}
            onClick={preventDefault}
          >
            Dashboard
          </NavbarItem>
          <NavbarItem
            icon={<Icon name="activity" size={16} />}
            aria-current="page"
            onClick={preventDefault}
          >
            Investigations
          </NavbarItem>
          <NavbarItem
            icon={<Icon name="database" size={16} />}
            onClick={preventDefault}
          >
            Data
          </NavbarItem>
          <NavbarSeparator />
          <NavbarSubmenu
            label="Entities"
            icon={<Icon name="box" size={16} />}
            defaultOpen
          >
            <NavbarSubmenuItem href="#" onClick={preventDefault}>Sectors</NavbarSubmenuItem>
            <NavbarSubmenuItem href="#" onClick={preventDefault}>Organizations</NavbarSubmenuItem>
            <NavbarSubmenuItem href="#" onClick={preventDefault}>Individuals</NavbarSubmenuItem>
          </NavbarSubmenu>
        </Navbar>
      </Box>
      <Box sx={{ flex: 1, overflow: 'auto', p: 3 }}>
        <Alert severity="warning" sx={{ mb: 2 }}>
          <strong>Temporary spike — not production code.</strong> This screen only
          renders design-system components with fake data to visually check
          Navbar/NavbarItem/NavbarSubmenu/ProductSwitcher. It is not linked from
          any real navigation and should be deleted after review.
          <br />
          ⚠ ProductSwitcher colors are reused/unvalidated tokens (see this
          component&apos;s .rfc.md in the filigran-design-system repo) — not a
          reliable reference yet.
        </Alert>
        <Button variant="outlined" onClick={onToggleMode} sx={{ mb: 2 }}>
          Toggle theme (currently: {mode})
        </Button>
        <Typography variant="h4" gutterBottom>
          FDS components spike
        </Typography>
        <Typography variant="body1">
          Placeholder content area — the sidebar on the left is the real
          `@filigran/design-system` Navbar, composed with fake menu items, a
          fake user row, and a fake product list for ProductSwitcher.
        </Typography>
      </Box>
    </Box>
  );
};

/**
 * Route entry point. Builds a local MUI theme directly from `ThemeDark`/
 * `ThemeLight` (no GraphQL `settings` fragment involved, per the
 * no-real-integration requirement) and toggles between them with local
 * state only — this never touches the app-wide `AppThemeProvider`/
 * `useDocumentThemeModifier` state, keeping the spike fully isolated.
 */
const FdsComponentsSpikeScreen = () => {
  const [mode, setMode] = useState<'dark' | 'light'>('dark');

  const muiTheme = useMemo(
    () => createTheme((mode === 'dark' ? ThemeDark() : ThemeLight()) as ThemeOptions),
    [mode],
  );

  return (
    <StyledEngineProvider injectFirst>
      <ThemeProvider theme={muiTheme}>
        {/* Same convention as other top-level route roots (private/Index.tsx,
            public/PublicRoot.tsx): a fresh top-level route needs its own
            CssBaseline. Without it, native elements (e.g. NavbarItem's
            underlying <button>) keep the browser's default chrome/background,
            since dist/index.css deliberately ships without Tailwind preflight. */}
        <CssBaseline />
        <SpikeContent
          mode={mode}
          onToggleMode={() => setMode((current) => (current === 'dark' ? 'light' : 'dark'))}
        />
      </ThemeProvider>
    </StyledEngineProvider>
  );
};

export default FdsComponentsSpikeScreen;
