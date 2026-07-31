// LOCAL-ONLY REAL SWAP — never committed, never pushed (see report). This
// replaces the MUI Drawer/MenuList/LeftBarItem rendering with the real
// @filigran/design-system Navbar/NavbarItem/NavbarSubmenu components, wired
// to the exact same permission logic (`Security`, `useGranted`,
// `useIsHiddenEntities`) and real routes as before. `LeftBarItem.tsx` is no
// longer used by this file but is left in place untouched (still imported
// elsewhere? no — only referenced here previously). Icons switch from
// MUI/mdi-material-ui to FDS's own `Icon` registry (includes several
// `custom/*` icons that map 1:1 to OpenCTI entity types).
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import { Icon, Navbar, NavbarItem, NavbarSeparator, NavbarSubmenu, NavbarSubmenuItem } from '@filigran/design-system';
import '@filigran/design-system/dist/index.css';
import React, { useRef, useState } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { useLocation, useNavigate } from 'react-router-dom';
import { THEME_LIGHT_DEFAULT_BACKGROUND, THEME_LIGHT_DEFAULT_PAPER } from '../../../components/ThemeLight';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import logoFiligran from '../../../static/images/logo_filigran_full.svg';
import Security from '../../../utils/Security';
import useAuth from '../../../utils/hooks/useAuth';
import useFdsThemeScope from '../../../utils/hooks/useFdsThemeScope';
import { useHiddenEntities, useIsHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useGranted, {
  AUTOMATION_AUTMANAGE,
  BYPASS,
  CSVMAPPERS,
  EXPLORE,
  INGESTION,
  INGESTION_SETINGESTIONS,
  INVESTIGATION,
  KNOWLEDGE,
  KNOWLEDGE_KNASKIMPORT,
  KNOWLEDGE_KNUPDATE,
  KNOWLEDGE_KNUPDATE_KNDELETE,
  MODULES,
  PIRAPI,
  SETTINGS_FILEINDEXING,
  SETTINGS_SECURITYACTIVITY,
  SETTINGS_SETACCESSES,
  SETTINGS_SETAUTH,
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETCUSTOMIZATION,
  SETTINGS_SETDISSEMINATION,
  SETTINGS_SETKILLCHAINPHASES,
  SETTINGS_SETLABELS,
  SETTINGS_SETMANAGEXTMHUB,
  SETTINGS_SETMARKINGS,
  SETTINGS_SETPARAMETERS,
  SETTINGS_SETSTATUSTEMPLATES,
  SETTINGS_SETVOCABULARIES,
  SETTINGS_SUPPORT,
  TAXIIAPI,
  VIRTUAL_ORGANIZATION_ADMIN,
} from '../../../utils/hooks/useGranted';
import useHelper from '../../../utils/hooks/useHelper';
import useImportAccess from '../../../utils/hooks/useImportAccess';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import useTopBanner from '../../../utils/hooks/useTopBanner';
import { LeftBarHeader } from './LeftBarHeader';
import LogoTextOrange from '../../../static/images/logo_text_orange.svg';
import LogoCollapsedOrange from '../../../static/images/logo_orange.svg';
import { shouldOpenInNewTabMouseEvent } from 'src/utils/domEvent';

export const SMALL_BAR_WIDTH = 55;
export const OPEN_BAR_WIDTH = 180;

const leftBarQuery = graphql`
  query LeftBarQuery {
    settings {
      platform_whitemark
    }
  }
`;

const LeftBarComponent = ({ queryRef }) => {
  const theme = useTheme();
  // Root of the FDS subtree: bridges OpenCTI's current light/dark mode to
  // the .dark/.light scope classes the Navbar's own CSS variables rely on
  // (per useFdsThemeScope's docstring — used as-is, hook itself untouched).
  const fdsThemeContainerRef = useRef(null);
  useFdsThemeScope(fdsThemeContainerRef);
  const { t_i18n } = useFormatter();
  const {
    me: { submenu_auto_collapse, submenu_show_icons, draftContext },
  } = useAuth();
  const { isFeatureEnable } = useHelper();
  const navigate = useNavigate();
  const location = useLocation();
  const { hasOnlyAccessToImportDraftTab } = useImportAccess();
  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  const isGrantedToImport = useGranted([KNOWLEDGE_KNASKIMPORT]) || hasOnlyAccessToImportDraftTab;
  const isGrantedToProcessing = useGranted([KNOWLEDGE_KNUPDATE, AUTOMATION_AUTMANAGE, CSVMAPPERS]);
  const isGrantedToSharing = useGranted([TAXIIAPI]);
  const isGrantedToManage = useGranted([BYPASS]);
  const isGrantedToParameters = useGranted([SETTINGS_SETPARAMETERS]);
  const isGrantedToLabels = useGranted([SETTINGS_SETLABELS]);
  const isGrantedToVocabularies = useGranted([SETTINGS_SETVOCABULARIES]);
  const isGrantedToKillChainPhases = useGranted([SETTINGS_SETKILLCHAINPHASES]);
  const isGrantedToCaseTemplates = useGranted([SETTINGS_SETCASETEMPLATES]);
  const isGrantedToStatusTemplates = useGranted([SETTINGS_SETSTATUSTEMPLATES]);
  const isGrantedToTaxonomies = isGrantedToLabels || isGrantedToVocabularies || isGrantedToKillChainPhases || isGrantedToCaseTemplates || isGrantedToStatusTemplates;
  const isGrantedToFileIndexing = useGranted([SETTINGS_FILEINDEXING]);
  const isGrantedToExperience = useGranted([SETTINGS_SETPARAMETERS, SETTINGS_SUPPORT, SETTINGS_SETMANAGEXTMHUB]);
  const isGrantedToDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const isOrganizationAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const isGrantedToCustomization = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const isGrantedToSecurity = useGranted([SETTINGS_SETMARKINGS, SETTINGS_SETACCESSES, SETTINGS_SETDISSEMINATION, SETTINGS_SETAUTH]);
  const isGrantedToAudit = useGranted([SETTINGS_SECURITYACTIVITY]);
  const isGrantedToExplore = useGranted([EXPLORE]);
  const hasXtmHubAccess = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const isDataHealthEnabled = isFeatureEnable('DATA_SANITY_MANAGER');

  const [selectedMenu, setSelectedMenu] = useState(
    JSON.parse(localStorage.getItem('selectedMenu') ?? '[]'),
  );
  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );

  const data = usePreloadedQuery(leftBarQuery, queryRef);

  const navOpenLogo = draftContext ? LogoTextOrange : theme.logo;
  const navCloseLogo = draftContext ? LogoCollapsedOrange : theme.logo_collapsed;
  let logo = navOpen ? navOpenLogo : navCloseLogo;

  const addMenuUnique = (menu) => {
    const joined = selectedMenu.concat(menu);
    return joined.filter((value, index, array) => array.indexOf(value) === index);
  };
  const removeMenuUnique = (menu) => {
    return selectedMenu.filter((value) => value !== menu);
  };
  const handleToggle = () => {
    setSelectedMenu([]);
    localStorage.setItem('navOpen', String(!navOpen));
    window.dispatchEvent(new StorageEvent('storage', { key: 'navOpen' }));
    localStorage.setItem('selectedMenu', JSON.stringify([]));
    setNavOpen(!navOpen);
    MESSAGING$.toggleNav.next('toggle');
  };
  const handleSelectedMenuOpen = (menu) => {
    const updatedMenu = (navOpen && submenu_auto_collapse) ? addMenuUnique(menu) : [menu];
    setSelectedMenu(updatedMenu);
  };
  const handleSelectedMenuClose = () => {
    setSelectedMenu([]);
  };
  // Adapts the FDS NavbarSubmenu's `onOpenChange(open: boolean)` shape to
  // the pre-existing open/close semantics above, preserving them exactly:
  // opening still respects the submenu_auto_collapse preference (single vs.
  // accumulating), closing still only removes the one closed menu (so other
  // open sections stay open when submenu_auto_collapse is off).
  const handleSubmenuOpenChange = (menu, open) => {
    if (open) {
      handleSelectedMenuOpen(menu);
      return;
    }
    if (submenu_auto_collapse) {
      handleSelectedMenuClose();
      return;
    }
    const updatedMenu = removeMenuUnique(menu);
    setSelectedMenu(updatedMenu);
    localStorage.setItem('selectedMenu', JSON.stringify(updatedMenu));
  };
  const handleGoToPage = (event, link) => {
    // NavbarSubmenuItem renders a real <a href>; without preventDefault the
    // browser's own navigation would race the router's, causing a full
    // reload (and, per the demo screen's real-backend testing, a lost
    // session). Same fix as the proven pattern in FdsRealNavDemo.tsx.
    event.preventDefault();
    if (shouldOpenInNewTabMouseEvent(event)) {
      window.open(link, '_blank');
    } else {
      navigate(link);
    }
  };
  const hiddenEntities = useHiddenEntities();
  const hideAnalyses = useIsHiddenEntities(
    'Report',
    'Grouping',
    'Note',
    'Malware-Analysis',
    'Security-Coverage',
  );
  const hideEvents = useIsHiddenEntities(
    'stix-sighting-relationship',
    'Incident',
    'Observed-Data',
  );
  const hideObservations = useIsHiddenEntities(
    'Stix-Cyber-Observable',
    'Artifact',
    'Indicator',
    'Infrastructure',
  );
  const hideThreats = useIsHiddenEntities(
    'Threat-Actor-Group',
    'Threat-Actor-Individual',
    'Intrusion-Set',
    'Campaign',
  );
  const hideEntities = useIsHiddenEntities(
    'Sector',
    'Event',
    'Organization',
    'Security-platforms',
    'System',
    'Individual',
  );
  const hideCases = useIsHiddenEntities(
    'Case-Incident',
    'Feedback',
    'Case-Rfi',
    'Case-Rft',
    'Task',
  );
  const hideArsenal = useIsHiddenEntities(
    'Malware',
    'Channel',
    'Tool',
    'Vulnerability',
  );
  const hideTechniques = useIsHiddenEntities(
    'Attack-Pattern',
    'Narrative',
    'Course-Of-Action',
    'Data-Component',
    'Data-Source',
  );
  const hideLocations = useIsHiddenEntities(
    'Region',
    'Administrative-Area',
    'Country',
    'City',
    'Position',
  );

  const { isTrashEnable } = useHelper();

  const {
    bannerSettings: { bannerHeightNumber },
    settings: {
      platform_openaev_url: openAEVUrl,
      // platform_enterprise_edition: ee,
      platform_xtmhub_url: xtmhubUrl,
      xtm_hub_registration_status: xtmhubStatus,
    },
  } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const { height: topBannerHeight } = useTopBanner();

  const isLightTheme = theme.palette.mode === 'light';
  const getBackground = () => {
    if (isLightTheme) {
      return `linear-gradient(100deg, ${THEME_LIGHT_DEFAULT_BACKGROUND} 0%, ${THEME_LIGHT_DEFAULT_PAPER} 100%)`;
    }
    const start = theme.palette.background?.gradient?.start ?? theme.palette.background?.default;
    const end = theme.palette.background?.gradient?.end ?? theme.palette.background?.secondary;
    return `linear-gradient(100deg, ${start} 0%, ${end} 100%)`;
  };

  // Exact port of LeftBarItem.tsx's isSelected — same rules (exact vs.
  // prefix match, same data/draft special-case) so aria-current stays
  // correct after the swap.
  const isSelected = (itemLink, itemExact) => {
    if (itemExact) {
      return location.pathname === itemLink;
    }
    if (itemLink === '/dashboard/data' && location.pathname.includes('/import/draft/')) {
      return false;
    }
    return location.pathname === itemLink || location.pathname.startsWith(`${itemLink}/`);
  };

  // Exact port of LeftBarItem.tsx's visibleSubItems filter.
  const visibleSubItems = (subItems) => subItems.filter(
    (item) => item.granted !== false && (!item.type || !hiddenEntities.includes(item.type)),
  );

  // Renders one top-level entry as either a plain NavbarItem (no subItems)
  // or a NavbarSubmenu (subItems present) — mirrors LeftBarItem.tsx's
  // single-component dual behavior.
  const renderNavItem = ({
    id, icon, label, link, exact, subItems,
  }) => {
    const items = subItems ? visibleSubItems(subItems) : [];
    if (!subItems || items.length === 0) {
      return (
        <NavbarItem
          key={id ?? link}
          icon={<Icon name={icon} />}
          onClick={(e) => handleGoToPage(e, link)}
          aria-current={isSelected(link, exact) ? 'page' : undefined}
        >
          {label}
        </NavbarItem>
      );
    }
    return (
      <NavbarSubmenu
        key={id}
        label={label}
        icon={<Icon name={icon} />}
        open={selectedMenu.includes(id)}
        onOpenChange={(open) => handleSubmenuOpenChange(id, open)}
      >
        {items.map((item) => (
          <NavbarSubmenuItem
            key={item.link}
            href={item.link}
            icon={item.icon ? <Icon name={item.icon} /> : undefined}
            showIcon={submenu_show_icons}
            onClick={(e) => handleGoToPage(e, item.link)}
            aria-current={isSelected(item.link, item.exact) ? 'page' : undefined}
          >
            {item.label}
          </NavbarSubmenuItem>
        ))}
      </NavbarSubmenu>
    );
  };

  return (
    <div
      ref={fdsThemeContainerRef}
      style={{
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: getBackground(),
        borderRight: '1px solid transparent',
        width: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH,
        // The old <Drawer variant="permanent"> provided flexShrink:0/flexGrow:0
        // for free; a plain <div> doesn't, so without this the sibling flex
        // Box in Index.tsx squeezes this bar down to ~56px once expanded
        // (180px), clipping the wider Navbar content via overflow:hidden.
        flexShrink: 0,
        flexGrow: 0,
        zIndex: 999,
        top: 0,
        height: '100vh',
        transition: theme.transitions.create('width', {
          easing: theme.transitions.easing.easeInOut,
          duration: theme.transitions.duration.enteringScreen,
        }),
      }}
    >
      <LeftBarHeader
        logo={logo}
        logoCollapsed={navCloseLogo}
        navOpen={navOpen}
        bannerHeightNumber={bannerHeightNumber}
        topBannerHeight={topBannerHeight}
        settingsMessagesBannerHeight={settingsMessagesBannerHeight}
        openAEVUrl={openAEVUrl}
        xtmhubUrl={xtmhubUrl}
        xtmhubStatus={xtmhubStatus}
        hasXtmHubAccess={hasXtmHubAccess}
      />

      <Navbar
        aria-label="Main navigation"
        collapsed={!navOpen}
        onCollapsedChange={handleToggle}
        style={{
          flex: 1,
          overflow: 'auto',
          overflowX: 'hidden',
          minHeight: 0,
          backgroundColor: 'transparent',
        }}
        footer={!data?.settings?.platform_whitemark && (
          <Stack
            direction="row"
            alignItems="center"
            gap={0.5}
            paddingLeft={2.5}
            marginBottom={1}
            minHeight={16}
          >
            {
              navOpen && (
                <Typography
                  component="span"
                  sx={{
                    fontFamily: 'IBM Plex Sans',
                    fontSize: '10px',
                    lineHeight: '16px',
                    opacity: 0.8,
                    color: theme.palette.text.tertiary,
                  }}
                >
                  {t_i18n('Made by')}
                </Typography>
              )
            }
            <img
              alt="logo"
              src={logoFiligran}
              width={navOpen ? 48 : 12}
              height="12"
              style={{
                opacity: 0.8,
                objectFit: 'cover',
                objectPosition: 'left center',
              }}
            />
          </Stack>
        )}
      >
        {!draftContext && renderNavItem({ label: t_i18n('Home'), icon: 'house', link: '/dashboard', exact: true })}

        <Security needs={[EXPLORE]}>
          {!draftContext && renderNavItem({
            id: 'dashboards',
            icon: 'chart-bar',
            label: t_i18n('Dashboards'),
            link: '/dashboard/workspaces/dashboards',
            subItems: [
              {
                granted: isGrantedToExplore,
                type: 'Dashboard',
                link: '/dashboard/workspaces/dashboards',
                label: t_i18n('Custom dashboards'),
                exact: true,
              },
              {
                granted: isGrantedToExplore,
                type: 'Dashboard',
                link: '/dashboard/workspaces/dashboards_public',
                label: t_i18n('Public dashboards'),
                exact: true,
              },
            ],
          })}
        </Security>

        <Security needs={[INVESTIGATION]}>
          {!draftContext && renderNavItem({ label: t_i18n('Investigations'), icon: 'compass', link: '/dashboard/workspaces/investigations' })}
        </Security>

        {draftContext && renderNavItem({ label: t_i18n('Draft overview'), icon: 'drafting-compass', link: `/dashboard/data/import/draft/${draftContext.id}` })}

        <Security needs={[PIRAPI]}>
          {!draftContext && renderNavItem({ label: t_i18n('PIR'), icon: 'radar', link: '/dashboard/pirs' })}
        </Security>

        <NavbarSeparator />

        <Security needs={[KNOWLEDGE]}>
          <>
            {!hideAnalyses && renderNavItem({
              id: 'analyses',
              icon: 'file-text',
              label: t_i18n('Analyses'),
              link: '/dashboard/analyses',
              subItems: [
                { type: 'Report', link: '/dashboard/analyses/reports', label: t_i18n('Reports'), icon: 'newspaper' },
                { type: 'Grouping', link: '/dashboard/analyses/groupings', label: t_i18n('Groupings'), icon: 'layers' },
                { type: 'Malware-Analysis', link: '/dashboard/analyses/malware_analyses', label: t_i18n('Malware analyses'), icon: 'flask-conical' },
                { type: 'Security-Coverage', link: '/dashboard/analyses/security_coverages', label: t_i18n('Security coverages'), icon: 'shield-check' },
                { type: 'Note', link: '/dashboard/analyses/notes', label: t_i18n('Notes'), icon: 'sticky-note' },
                { type: 'External-Reference', link: '/dashboard/analyses/external_references', label: t_i18n('External references'), icon: 'link-2' },
              ],
            })}

            {!hideCases && renderNavItem({
              id: 'cases',
              icon: 'briefcase',
              label: t_i18n('Cases'),
              link: '/dashboard/cases',
              subItems: [
                { type: 'Case-Incident', link: '/dashboard/cases/incidents', label: t_i18n('Incident responses'), icon: 'custom/case-incident' },
                { type: 'Case-Rfi', link: '/dashboard/cases/rfis', label: t_i18n('Requests for information'), icon: 'custom/case-rfi' },
                { type: 'Case-Rft', link: '/dashboard/cases/rfts', label: t_i18n('Requests for takedown'), icon: 'custom/case-rft' },
                { type: 'Task', link: '/dashboard/cases/tasks', label: t_i18n('Tasks'), icon: 'list-checks' },
                { type: 'Feedback', link: '/dashboard/cases/feedbacks', label: t_i18n('Feedbacks'), icon: 'message-square-text' },
              ],
            })}

            {!hideEvents && renderNavItem({
              id: 'events',
              icon: 'alarm-clock',
              label: t_i18n('Events'),
              link: '/dashboard/events',
              subItems: [
                { type: 'Incident', link: '/dashboard/events/incidents', label: t_i18n('Incidents'), icon: 'custom/fire' },
                { type: 'stix-sighting-relationship', link: '/dashboard/events/sightings', label: t_i18n('Sightings'), icon: 'eye' },
                { type: 'Observed-Data', link: '/dashboard/events/observed_data', label: t_i18n('Observed datas'), icon: 'satellite-dish' },
              ],
            })}

            {!hideObservations && renderNavItem({
              id: 'observations',
              icon: 'custom/binocular',
              label: t_i18n('Observations'),
              link: '/dashboard/observations',
              subItems: [
                { type: 'Stix-Cyber-Observable', link: '/dashboard/observations/observables', label: t_i18n('Observables'), icon: 'hexagon' },
                { type: 'Artifact', link: '/dashboard/observations/artifacts', label: t_i18n('Artifacts'), icon: 'files' },
                { type: 'Indicator', link: '/dashboard/observations/indicators', label: t_i18n('Indicators'), icon: 'custom/target' },
                { type: 'Infrastructure', link: '/dashboard/observations/infrastructures', label: t_i18n('Infrastructures'), icon: 'custom/infrastructure' },
              ],
            })}

            <NavbarSeparator />

            {!hideThreats && renderNavItem({
              id: 'threats',
              icon: 'shield-check',
              label: t_i18n('Threats'),
              link: '/dashboard/threats',
              subItems: [
                { type: 'Threat-Actor-Group', link: '/dashboard/threats/threat_actors_group', label: t_i18n('Threat actors (group)'), icon: 'users' },
                {
                  type: 'Threat-Actor-Individual',
                  link: '/dashboard/threats/threat_actors_individual',
                  label: t_i18n('Threat actors (individual)'),
                  icon: 'custom/threat-actor-individual',
                },
                { type: 'Intrusion-Set', link: '/dashboard/threats/intrusion_sets', label: t_i18n('Intrusion sets'), icon: 'custom/intrusion-set' },
                { type: 'Campaign', link: '/dashboard/threats/campaigns', label: t_i18n('Campaigns'), icon: 'chess-knight' },
              ],
            })}

            {!hideArsenal && renderNavItem({
              id: 'arsenal',
              icon: 'layers-2',
              label: t_i18n('Arsenal'),
              link: '/dashboard/arsenal',
              subItems: [
                { type: 'Malware', link: '/dashboard/arsenal/malwares', label: t_i18n('Malwares'), icon: 'custom/malware' },
                { type: 'Channel', link: '/dashboard/arsenal/channels', label: t_i18n('Channels'), icon: 'megaphone' },
                { type: 'Tool', link: '/dashboard/arsenal/tools', label: t_i18n('Tools'), icon: 'wrench' },
                { type: 'Vulnerability', link: '/dashboard/arsenal/vulnerabilities', label: t_i18n('Vulnerabilities'), icon: 'bug' },
              ],
            })}

            {!hideTechniques && renderNavItem({
              id: 'techniques',
              icon: 'network',
              label: t_i18n('Techniques'),
              link: '/dashboard/techniques',
              subItems: [
                { type: 'Attack-Pattern', link: '/dashboard/techniques/attack_patterns', label: t_i18n('Attack patterns'), icon: 'custom/attack-pattern' },
                { type: 'Narrative', link: '/dashboard/techniques/narratives', label: t_i18n('Narratives'), icon: 'message-square-more' },
                { type: 'Course-Of-Action', link: '/dashboard/techniques/courses_of_action', label: t_i18n('Courses of action'), icon: 'custom/course-of-action' },
                { type: 'Data-Component', link: '/dashboard/techniques/data_components', label: t_i18n('Data components'), icon: 'grid-3x2' },
                { type: 'Data-Source', link: '/dashboard/techniques/data_sources', label: t_i18n('Data sources'), icon: 'server' },
              ],
            })}

            {!hideEntities && renderNavItem({
              id: 'entities',
              icon: 'box',
              label: t_i18n('Entities'),
              link: '/dashboard/entities',
              subItems: [
                { type: 'Sector', link: '/dashboard/entities/sectors', label: t_i18n('Sectors'), icon: 'building-2' },
                { type: 'Event', link: '/dashboard/entities/events', label: t_i18n('Events'), icon: 'calendar' },
                { type: 'Organization', link: '/dashboard/entities/organizations', label: t_i18n('Organizations'), icon: 'landmark' },
                { type: 'SecurityPlatform', link: '/dashboard/entities/security_platforms', label: t_i18n('Security platforms'), icon: 'custom/security-platforms' },
                { type: 'System', link: '/dashboard/entities/systems', label: t_i18n('Systems'), icon: 'monitor' },
                { type: 'Individual', link: '/dashboard/entities/individuals', label: t_i18n('Individuals'), icon: 'user' },
              ],
            })}

            {!hideLocations && renderNavItem({
              id: 'locations',
              icon: 'map-pin',
              label: t_i18n('Locations'),
              link: '/dashboard/locations',
              subItems: [
                { type: 'Region', link: '/dashboard/locations/regions', label: t_i18n('Regions'), icon: 'earth' },
                { type: 'Country', link: '/dashboard/locations/countries', label: t_i18n('Countries'), icon: 'flag' },
                { type: 'Administrative-Area', link: '/dashboard/locations/administrative_areas', label: t_i18n('Administrative areas'), icon: 'map' },
                { type: 'City', link: '/dashboard/locations/cities', label: t_i18n('Cities'), icon: 'custom/city' },
                { type: 'Position', link: '/dashboard/locations/positions', label: t_i18n('Positions'), icon: 'locate' },
              ],
            })}
          </>
        </Security>

        <Security needs={[MODULES, KNOWLEDGE, TAXIIAPI, CSVMAPPERS, INGESTION]}>
          <NavbarSeparator />

          <>
            <Security needs={[MODULES, INGESTION, INGESTION_SETINGESTIONS]}>
              {!draftContext && renderNavItem({
                id: 'integrations',
                icon: 'share-2',
                label: t_i18n('Integrations'),
                link: '/dashboard/integrations',
              })}
            </Security>

            <Security needs={[MODULES, KNOWLEDGE, TAXIIAPI, CSVMAPPERS, INGESTION]}>
              {renderNavItem({
                id: 'data',
                icon: 'database',
                label: t_i18n('Data'),
                link: '/dashboard/data',
                subItems: [
                  { granted: isGrantedToKnowledge, link: '/dashboard/data/entities', label: t_i18n('Entities'), icon: 'box' },
                  { granted: isGrantedToKnowledge, link: '/dashboard/data/relationships', label: t_i18n('Relationships'), icon: 'custom/relationship' },
                  { granted: isGrantedToImport && !draftContext, link: '/dashboard/data/import', label: t_i18n('Import'), icon: 'cloud-upload' },
                  { granted: isGrantedToProcessing && !draftContext, link: '/dashboard/data/processing', label: t_i18n('Processing'), icon: 'refresh-cw' },
                  { granted: isGrantedToSharing && !draftContext, link: '/dashboard/data/sharing', label: t_i18n('Data sharing'), icon: 'upload' },
                  { granted: isGrantedToManage && !draftContext, link: '/dashboard/data/restriction', label: t_i18n('Restriction'), icon: 'lock' },
                  { granted: isDataHealthEnabled && isGrantedToManage && !draftContext, link: '/dashboard/data/health', label: t_i18n('Health'), icon: 'activity' },
                  { granted: isTrashEnable() && isGrantedToDelete && !draftContext, link: '/dashboard/trash', label: t_i18n('Trash'), icon: 'trash-2' },
                ],
              })}
            </Security>
          </>
        </Security>

        <Security needs={[
          VIRTUAL_ORGANIZATION_ADMIN,
          SETTINGS_SETPARAMETERS,
          SETTINGS_SETACCESSES,
          SETTINGS_SETAUTH,
          SETTINGS_SETMARKINGS,
          SETTINGS_SETDISSEMINATION,
          SETTINGS_SETCUSTOMIZATION,
          SETTINGS_SETLABELS,
          SETTINGS_SETVOCABULARIES,
          SETTINGS_SETCASETEMPLATES,
          SETTINGS_SETSTATUSTEMPLATES,
          SETTINGS_SETKILLCHAINPHASES,
          SETTINGS_SECURITYACTIVITY,
          SETTINGS_FILEINDEXING,
          SETTINGS_SUPPORT,
          SETTINGS_SETMANAGEXTMHUB,
        ]}
        >
          <NavbarSeparator />
          {!draftContext && renderNavItem({
            id: 'settings',
            icon: 'settings',
            label: t_i18n('Settings'),
            link: '/dashboard/settings',
            subItems: [
              { granted: isGrantedToParameters, link: '/dashboard/settings', label: t_i18n('Parameters'), exact: true, icon: 'sliders-horizontal' },
              { granted: isGrantedToSecurity || isOrganizationAdmin, link: '/dashboard/settings/accesses', label: t_i18n('Security'), icon: 'shield' },
              { granted: isGrantedToCustomization, link: '/dashboard/settings/customization', label: t_i18n('Customization'), icon: 'wrench' },
              { granted: isGrantedToTaxonomies, link: '/dashboard/settings/vocabularies', label: t_i18n('Taxonomies'), icon: 'tag' },
              { granted: isGrantedToAudit, link: '/dashboard/settings/activity', label: t_i18n('Activity'), icon: 'activity' },
              { granted: isGrantedToFileIndexing, link: '/dashboard/settings/file_indexing', label: t_i18n('File indexing'), icon: 'file-search' },
              { granted: isGrantedToExperience, link: '/dashboard/settings/experience', label: t_i18n('Filigran Experience'), icon: 'custom/filigran' },
            ],
          })}
        </Security>
      </Navbar>
    </div>
  );
};

const LeftBar = () => {
  const queryRef = useQueryLoading(leftBarQuery, {});
  return (
    <>
      {queryRef && (
        <React.Suspense>
          <LeftBarComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default LeftBar;
