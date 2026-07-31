import React from 'react';
import { useNavigate } from 'react-router-dom';
import { StyledEngineProvider, ThemeProvider, createTheme } from '@mui/material/styles';
import type { ThemeOptions } from '@mui/material/styles/createTheme';
import CssBaseline from '@mui/material/CssBaseline';
import GlobalStyles from '@mui/material/GlobalStyles';
import Box from '@mui/material/Box';
import Alert from '@mui/material/Alert';
import Typography from '@mui/material/Typography';
import { Navbar, NavbarItem, NavbarSeparator, NavbarSubmenu, NavbarSubmenuItem, Icon } from '@filigran/design-system';
import '@filigran/design-system/dist/index.css';
import ThemeDark from '../components/ThemeDark';

/**
 * ============================================================================
 * LOCAL-ONLY DEMO — NEVER COMMIT, NEVER PUSH — SAFE TO DELETE ANY TIME.
 * ============================================================================
 *
 * Requested for an urgent 13:30 demo (2026-07-30). Goal: show the real
 * OpenCTI navigation *structure* (real top-level items, real submenus, real
 * labels, real `/dashboard/...` routes copied 1:1 from
 * `LeftBar.jsx`) rendered with the new @filigran/design-system
 * `Navbar`/`NavbarItem`/`NavbarSubmenu`, instead of the fake spike data in
 * `FdsComponentsSpikeScreen.tsx`.
 *
 * WHY THIS IS A SEPARATE FILE INSTEAD OF EDITING LeftBar.jsx IN PLACE:
 * no OpenCTI backend is reachable in this environment right now (checked:
 * no process listening on :4000 or any other port for opencti-graphql; the
 * only relevant docker containers present — redis/elasticsearch/minio/
 * rabbitmq — belong to a *different* worktree/session on this shared host,
 * `sandyghs-redesigned-engine`, and its rabbitmq container's bind mount
 * confirms this and is currently broken). `LeftBar.jsx`'s default export
 * loads `leftBarQuery` via Relay's `useQueryLoading`, and `LeftBarComponent`
 * calls `useAuth()` (throws without a live session) plus several other
 * backend-derived hooks (`useHiddenEntities`, `useImportAccess`, etc.).
 * None of that can resolve without a backend, so editing LeftBar.jsx's
 * internals in place would render *nothing at all* here regardless of what
 * this task changes — the blocker is infra, not the component swap itself.
 * `LeftBar.jsx` / `LeftBarItem.tsx` / `LeftBarHeader.tsx` are therefore left
 * completely untouched, exactly as in the original spike.
 *
 * WHAT IS REAL vs STUBBED HERE:
 *  - REAL: every label, every `/dashboard/...` route, and the overall
 *    top-level + submenu structure (copied from `LeftBar.jsx`, English
 *    strings, which are the same strings `t_i18n(...)` resolves to in the
 *    `en-us` locale).
 *  - REAL: clicking an item calls the real `useNavigate()` from
 *    `react-router-dom` against the app's real router — the URL bar and
 *    router state genuinely change, exactly like production navigation.
 *  - STUBBED: permission gating. Every `Security needs={[...]}` /
 *    `isGrantedToX` check in the real file requires a live session's
 *    capabilities; with none available, every item here is simply always
 *    shown (equivalent to an all-permissions admin). Permission-based
 *    show/hide has NOT been verified against a live backend — flagged
 *    explicitly in the report, not resolved here.
 *  - STUBBED: destination pages. Clicking a real-looking nav item navigates
 *    the real router to the real path, but that destination page will
 *    itself show its own loading/error state, since no GraphQL backend is
 *    running to serve it any data.
 *
 * Default theme: this app's own real fallback (`AppThemeProvider.tsx`,
 * `defaultTheme.name = 'Dark'`, used whenever no per-user/platform
 * `platform_theme` override exists) is Dark — matches the default used
 * below. The known Navbar-gradient-frozen-in-light-mode bug (see
 * `FdsComponentsSpikeScreen.tsx`) is therefore not hit by default; only
 * relevant if a user/platform profile explicitly overrides to a Light theme.
 *
 * `useFdsThemeScope` is intentionally NOT used here: this demo is pinned to
 * Dark only (matching the real default), so there is no light/dark toggle
 * to bridge.
 */

const preventDefaultAndNavigate = (
  navigate: ReturnType<typeof useNavigate>,
  path: string,
) => (event: React.MouseEvent) => {
  event.preventDefault();
  navigate(path);
};

const RealNavContent = () => {
  const navigate = useNavigate();
  const go = (path: string) => preventDefaultAndNavigate(navigate, path);

  return (
    <Box sx={{ display: 'flex', height: '100vh', width: '100%', bgcolor: 'background.default' }}>
      {/* Same native-<button>-appearance reset as FdsComponentsSpikeScreen.tsx,
          scoped to this demo's own container only (see that file for why). */}
      <GlobalStyles
        styles={{
          '.fds-real-nav-demo-scope button': {
            appearance: 'none',
            WebkitAppearance: 'none',
            backgroundColor: 'transparent',
            backgroundImage: 'none',
          },
        }}
      />
      <Box className="fds-real-nav-demo-scope dark" sx={{ height: '100%', flexShrink: 0, overflowY: 'auto' }}>
        <Navbar aria-label="OpenCTI navigation (local demo, real structure)">
          <NavbarItem icon={<Icon name="layout-dashboard" size={16} />} onClick={go('/dashboard')}>
            Home
          </NavbarItem>

          <NavbarSubmenu label="Dashboards" icon={<Icon name="chart-bar" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/workspaces/dashboards" onClick={go('/dashboard/workspaces/dashboards')}>Custom dashboards</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/workspaces/dashboards_public" onClick={go('/dashboard/workspaces/dashboards_public')}>Public dashboards</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarItem icon={<Icon name="search" size={16} />} onClick={go('/dashboard/workspaces/investigations')}>
            Investigations
          </NavbarItem>

          <NavbarItem icon={<Icon name="radar" size={16} />} onClick={go('/dashboard/pirs')}>
            PIR
          </NavbarItem>

          <NavbarSeparator />

          <NavbarSubmenu label="Analyses" icon={<Icon name="file-text" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/analyses/reports" onClick={go('/dashboard/analyses/reports')}>Reports</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/analyses/groupings" onClick={go('/dashboard/analyses/groupings')}>Groupings</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/analyses/malware_analyses" onClick={go('/dashboard/analyses/malware_analyses')}>Malware analyses</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/analyses/security_coverages" onClick={go('/dashboard/analyses/security_coverages')}>Security coverages</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/analyses/notes" onClick={go('/dashboard/analyses/notes')}>Notes</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/analyses/external_references" onClick={go('/dashboard/analyses/external_references')}>External references</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Cases" icon={<Icon name="briefcase" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/cases/incidents" onClick={go('/dashboard/cases/incidents')}>Incident responses</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/cases/rfis" onClick={go('/dashboard/cases/rfis')}>Requests for information</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/cases/rfts" onClick={go('/dashboard/cases/rfts')}>Requests for takedown</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/cases/tasks" onClick={go('/dashboard/cases/tasks')}>Tasks</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/cases/feedbacks" onClick={go('/dashboard/cases/feedbacks')}>Feedbacks</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Events" icon={<Icon name="alarm-clock" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/events/incidents" onClick={go('/dashboard/events/incidents')}>Incidents</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/events/sightings" onClick={go('/dashboard/events/sightings')}>Sightings</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/events/observed_data" onClick={go('/dashboard/events/observed_data')}>Observed datas</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Observations" icon={<Icon name="file-search" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/observations/observables" onClick={go('/dashboard/observations/observables')}>Observables</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/observations/artifacts" onClick={go('/dashboard/observations/artifacts')}>Artifacts</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/observations/indicators" onClick={go('/dashboard/observations/indicators')}>Indicators</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/observations/infrastructures" onClick={go('/dashboard/observations/infrastructures')}>Infrastructures</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Threats" icon={<Icon name="shield" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/threats/threat_actors_group" onClick={go('/dashboard/threats/threat_actors_group')}>Threat actors (group)</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/threats/threat_actors_individual" onClick={go('/dashboard/threats/threat_actors_individual')}>Threat actors (individual)</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/threats/intrusion_sets" onClick={go('/dashboard/threats/intrusion_sets')}>Intrusion sets</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/threats/campaigns" onClick={go('/dashboard/threats/campaigns')}>Campaigns</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Arsenal" icon={<Icon name="shield-check" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/arsenal/malwares" onClick={go('/dashboard/arsenal/malwares')}>Malwares</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/arsenal/channels" onClick={go('/dashboard/arsenal/channels')}>Channels</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/arsenal/tools" onClick={go('/dashboard/arsenal/tools')}>Tools</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/arsenal/vulnerabilities" onClick={go('/dashboard/arsenal/vulnerabilities')}>Vulnerabilities</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Techniques" icon={<Icon name="network" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/techniques/attack_patterns" onClick={go('/dashboard/techniques/attack_patterns')}>Attack patterns</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/techniques/narratives" onClick={go('/dashboard/techniques/narratives')}>Narratives</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/techniques/courses_of_action" onClick={go('/dashboard/techniques/courses_of_action')}>Courses of action</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/techniques/data_components" onClick={go('/dashboard/techniques/data_components')}>Data components</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/techniques/data_sources" onClick={go('/dashboard/techniques/data_sources')}>Data sources</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Entities" icon={<Icon name="box" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/entities/sectors" onClick={go('/dashboard/entities/sectors')}>Sectors</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/entities/events" onClick={go('/dashboard/entities/events')}>Events</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/entities/organizations" onClick={go('/dashboard/entities/organizations')}>Organizations</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/entities/security_platforms" onClick={go('/dashboard/entities/security_platforms')}>Security platforms</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/entities/systems" onClick={go('/dashboard/entities/systems')}>Systems</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/entities/individuals" onClick={go('/dashboard/entities/individuals')}>Individuals</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Locations" icon={<Icon name="map-pin" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/locations/regions" onClick={go('/dashboard/locations/regions')}>Regions</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/locations/countries" onClick={go('/dashboard/locations/countries')}>Countries</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/locations/administrative_areas" onClick={go('/dashboard/locations/administrative_areas')}>Administrative areas</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/locations/cities" onClick={go('/dashboard/locations/cities')}>Cities</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/locations/positions" onClick={go('/dashboard/locations/positions')}>Positions</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSeparator />

          <NavbarSubmenu label="Data" icon={<Icon name="database" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/data/entities" onClick={go('/dashboard/data/entities')}>Entities</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/data/relationships" onClick={go('/dashboard/data/relationships')}>Relationships</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/data/import" onClick={go('/dashboard/data/import')}>Import</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/data/processing" onClick={go('/dashboard/data/processing')}>Processing</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/data/sharing" onClick={go('/dashboard/data/sharing')}>Data sharing</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/data/restriction" onClick={go('/dashboard/data/restriction')}>Restriction</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/trash" onClick={go('/dashboard/trash')}>Trash</NavbarSubmenuItem>
          </NavbarSubmenu>

          <NavbarSubmenu label="Settings" icon={<Icon name="settings" size={16} />}>
            <NavbarSubmenuItem href="/dashboard/settings" onClick={go('/dashboard/settings')}>Parameters</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/settings/accesses" onClick={go('/dashboard/settings/accesses')}>Security</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/settings/customization" onClick={go('/dashboard/settings/customization')}>Customization</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/settings/vocabularies" onClick={go('/dashboard/settings/vocabularies')}>Taxonomies</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/settings/activity" onClick={go('/dashboard/settings/activity')}>Activity</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/settings/file_indexing" onClick={go('/dashboard/settings/file_indexing')}>File indexing</NavbarSubmenuItem>
            <NavbarSubmenuItem href="/dashboard/settings/experience" onClick={go('/dashboard/settings/experience')}>Filigran Experience</NavbarSubmenuItem>
          </NavbarSubmenu>
        </Navbar>
      </Box>
      <Box sx={{ flex: 1, overflow: 'auto', p: 3 }}>
        <Alert severity="warning" sx={{ mb: 2 }}>
          <strong>Local-only demo — never committed.</strong> Real menu labels
          and real `/dashboard/...` routes, copied from `LeftBar.jsx`. No
          backend is running here, so permission gating is stubbed to
          &quot;everything granted&quot; (not live-verified) and destination
          pages will show their own loading/error state.
        </Alert>
        <Typography variant="h4" gutterBottom>
          Real navigation structure — FDS Navbar (local demo)
        </Typography>
        <Typography variant="body1">
          Click any item: the URL bar and router genuinely change (real
          `useNavigate`), same as production. `LeftBar.jsx` / `LeftBarItem.tsx`
          are untouched.
        </Typography>
      </Box>
    </Box>
  );
};

const muiTheme = createTheme(ThemeDark() as ThemeOptions);

const FdsRealNavDemo = () => (
  <StyledEngineProvider injectFirst>
    <ThemeProvider theme={muiTheme}>
      <CssBaseline />
      <RealNavContent />
    </ThemeProvider>
  </StyledEngineProvider>
);

export default FdsRealNavDemo;
