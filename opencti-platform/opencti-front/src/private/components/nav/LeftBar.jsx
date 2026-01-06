import {
  AccountBalanceOutlined,
  ArchitectureOutlined,
  AssignmentOutlined,
  BiotechOutlined,
  BugReportOutlined,
  CasesOutlined,
  ChevronLeft,
  ConstructionOutlined,
  DeleteOutlined,
  DescriptionOutlined,
  DiamondOutlined,
  DomainOutlined,
  EventOutlined,
  ExploreOutlined,
  FlagOutlined,
  Home,
  InsertChartOutlinedOutlined,
  LayersOutlined,
  LocalOfferOutlined,
  MapOutlined,
  PersonOutlined,
  PlaceOutlined,
  PublicOutlined,
  SecurityOutlined,
  SourceOutlined,
  SpeakerNotesOutlined,
  StorageOutlined,
  StreamOutlined,
  SubjectOutlined,
  SurroundSoundOutlined,
  TaskAltOutlined,
  TrackChanges,
  VisibilityOutlined,
  WebAssetOutlined,
  WifiTetheringOutlined,
  WorkspacesOutlined,
} from '@mui/icons-material';
import Divider from '@mui/material/Divider';
import Drawer from '@mui/material/Drawer';
import MenuList from '@mui/material/MenuList';
import { createStyles, makeStyles, useTheme } from '@mui/styles';
import {
  AccountMultipleOutline,
  ArchiveOutline,
  Binoculars,
  Biohazard,
  BriefcaseEditOutline,
  BriefcaseEyeOutline,
  BriefcaseRemoveOutline,
  BriefcaseSearchOutline,
  ChessKnight,
  ChevronRight,
  CityVariantOutline,
  CogOutline,
  Database,
  Fire,
  FlaskOutline,
  FolderTableOutline,
  GlobeModel,
  HexagonOutline,
  LaptopAccount,
  LockPattern,
  ProgressWrench,
  ServerNetwork,
  ShieldSearch,
  Timetable,
} from 'mdi-material-ui';
import React, { useRef, useState } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import useAuth from '../../../utils/hooks/useAuth';
import useDimensions from '../../../utils/hooks/useDimensions';
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
  SETTINGS_SETCASETEMPLATES,
  SETTINGS_SETCUSTOMIZATION,
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
import useHasOnlyAccessToImportDraftTab from '../../../utils/hooks/useHasOnlyAccessToImportDraftTab';
import useHelper from '../../../utils/hooks/useHelper';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import { LeftBarHeader } from './LeftBarHeader';
import LeftBarItem from './LeftBarItem';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import logoFiligran from '../../../static/images/logo_filigran.svg';

export const SMALL_BAR_WIDTH = 55;
export const OPEN_BAR_WIDTH = 180;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles((theme) => createStyles({
  drawerPaper: {
    width: SMALL_BAR_WIDTH,
    minHeight: '100vh',
    overflowX: 'hidden',
  },
  drawerPaperOpen: {
    width: OPEN_BAR_WIDTH,
    minHeight: '100vh',
    overflowX: 'hidden',
  },
  menuItemIcon: {
    color: theme.palette.text.primary,
  },
  menuItem: {
    paddingRight: 2,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
  },
  menuHoverItem: {
    height: 35,
    fontWeight: 500,
    fontSize: 14,
  },
  menuSubItem: {
    height: 25,
    fontWeight: 500,
    fontSize: 12,
  },
  menuItemText: {
    padding: '1px 0 0 8px',
    fontWeight: 500,
    fontSize: 14,
  },
  menuSubItemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    padding: '1px 0 0 8px',
    fontWeight: 500,
    fontSize: 12,
  },
  menuSubItemTextWithoutIcon: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    padding: '1px 0 0 0px',
    fontWeight: 500,
    fontSize: 12,
  },
  menuCollapseOpen: {
    width: OPEN_BAR_WIDTH,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
  },
  menuCollapse: {
    width: SMALL_BAR_WIDTH,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
  },
  menuLogoOpen: {
    width: OPEN_BAR_WIDTH,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
  },
  menuLogo: {
    width: SMALL_BAR_WIDTH,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
  },
  menuItemSmallText: {
    padding: '1px 0 0 20px',
  },
}));

const leftBarQuery = graphql`
  query LeftBarQuery {
    settings {
      platform_theme {
        theme_logo
        theme_logo_collapsed
      }
    }
  }
`;

const Separator = () => {
  const theme = useTheme();
  return (
    <Divider sx={{ border: `1px solid ${theme.palette.background.default}` }} />
  );
};

const LeftBarComponent = ({ queryRef }) => {
  const theme = useTheme();
  const ref = useRef();
  const { t_i18n } = useFormatter();
  const {
    me: { submenu_auto_collapse, submenu_show_icons, draftContext },
  } = useAuth();
  const navigate = useNavigate();
  const hasOnlyAccessToImportDraftTab = useHasOnlyAccessToImportDraftTab();
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
  const isGrantedToIngestion = useGranted([MODULES, INGESTION, INGESTION_SETINGESTIONS]);
  const isOrganizationAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const isGrantedToCustomization = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const isGrantedToSecurity = useGranted([SETTINGS_SETMARKINGS, SETTINGS_SETACCESSES]);
  const isGrantedToAudit = useGranted([SETTINGS_SECURITYACTIVITY]);
  const isGrantedToExplore = useGranted([EXPLORE]);
  const hasXtmHubAccess = useGranted([SETTINGS_SETMANAGEXTMHUB]);

  const [selectedMenu, setSelectedMenu] = useState(
    JSON.parse(localStorage.getItem('selectedMenu') ?? '[]'),
  );
  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );
  const classes = useStyles({ navOpen });

  const data = usePreloadedQuery(leftBarQuery, queryRef);
  const platformTheme = data.settings?.platform_theme;
  const logo = navOpen ? platformTheme?.theme_logo || theme.logo : platformTheme?.theme_logo_collapsed || theme.logo_collapsed;

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
  const handleSelectedMenuToggle = (menu) => {
    let updatedMenu;
    if (submenu_auto_collapse) {
      updatedMenu = selectedMenu.includes(menu) ? [] : [menu];
      setSelectedMenu(updatedMenu);
    } else {
      updatedMenu = selectedMenu.includes(menu)
        ? removeMenuUnique(menu)
        : addMenuUnique(menu);
      setSelectedMenu(updatedMenu);
    }
    localStorage.setItem('selectedMenu', JSON.stringify(updatedMenu));
  };
  const handleGoToPage = (event, link) => {
    if (event.ctrlKey) {
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
  const { dimension } = useDimensions();

  const isMobile = dimension.width < 768;

  const itemProps = {
    navOpen,
    selectedMenu,
    isMobile,
    classes,
    hiddenEntities,
    onMenuToggle: handleSelectedMenuToggle,
    onMenuOpen: handleSelectedMenuOpen,
    onMenuClose: handleSelectedMenuClose,
    onGoToPage: handleGoToPage,
    submenuShowIcons: submenu_show_icons,
  };

  return (
    <Drawer
      variant="permanent"
      classes={{
        paper: navOpen ? classes.drawerPaperOpen : classes.drawerPaper,
      }}
      slotProps={{
        paper: {
          sx: {
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden',
            backgroundColor: 'linear-gradient(90deg, #070D19, 0%, #0C1524, 100%)',
            borderRight: '1px solid transparent',
          },
        },
      }}
      sx={{
        width: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH,
        zIndex: 999,
        position: 'sticky',
        top: 0,
        height: '100vh',
        overflow: 'hidden',
        transition: theme.transitions.create('width', {
          easing: theme.transitions.easing.easeInOut,
          duration: theme.transitions.duration.enteringScreen,
        }),
      }}
    >
      <LeftBarHeader
        logo={logo}
        logoCollapsed={platformTheme?.theme_logo_collapsed}
        navOpen={navOpen}
        bannerHeightNumber={bannerHeightNumber}
        settingsMessagesBannerHeight={settingsMessagesBannerHeight}
        openAEVUrl={openAEVUrl}
        xtmhubUrl={xtmhubUrl}
        xtmhubStatus={xtmhubStatus}
        hasXtmHubAccess={hasXtmHubAccess}
      />

      <div
        ref={ref}
        aria-label="Main navigation"
        style={{
          overflow: 'auto',
          overflowX: 'hidden',
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          minHeight: 0,
          backgroundColor: 'transparent',
        }}
      >
        <MenuList component="nav">
          {!draftContext && (
            <LeftBarItem
              {...itemProps}
              label={t_i18n('Home')}
              icon={<Home />}
              link="/dashboard"
              exact
            />
          )}

          <Security needs={[EXPLORE]}>
            {!draftContext && (
              <LeftBarItem
                {...itemProps}
                id="dashboards"
                icon={<InsertChartOutlinedOutlined />}
                label="Dashboards"
                link="/dashboard/workspaces/dashboards"
                subItems={[
                  {
                    granted: isGrantedToExplore,
                    type: 'Dashboard',
                    link: '/dashboard/workspaces/dashboards',
                    label: 'Custom dashboards',
                    exact: true,
                  },
                  {
                    granted: isGrantedToExplore,
                    type: 'Dashboard',
                    link: '/dashboard/workspaces/dashboards_public',
                    label: 'Public dashboards',
                    exact: true,
                  },
                ]}
              />
            )}
          </Security>

          <Security needs={[INVESTIGATION]}>
            {!draftContext && (
              <LeftBarItem
                {...itemProps}
                label={t_i18n('Investigations')}
                icon={<ExploreOutlined />}
                link="/dashboard/workspaces/investigations"
              />
            )}
          </Security>

          {draftContext && (
            <LeftBarItem
              {...itemProps}
              label={t_i18n('Draft overview')}
              icon={<ArchitectureOutlined />}
              link={`/dashboard/data/import/draft/${draftContext.id}`}
            />
          )}

          <Security needs={[PIRAPI]}>
            {!draftContext && (
              <LeftBarItem
                {...itemProps}
                label={t_i18n('PIR')}
                icon={<TrackChanges />}
                link="/dashboard/pirs"
              />
            )}
          </Security>
        </MenuList>

        <Separator />

        <Security needs={[KNOWLEDGE]}>
          <MenuList component="nav">
            {!hideAnalyses && (
              <LeftBarItem
                {...itemProps}
                id="analyses"
                icon={<AssignmentOutlined />}
                label={t_i18n('Analyses')}
                link="/dashboard/analyses"
                subItems={[
                  { type: 'Report', link: '/dashboard/analyses/reports', label: t_i18n('Reports'), icon: <DescriptionOutlined fontSize="small" /> },
                  { type: 'Grouping', link: '/dashboard/analyses/groupings', label: t_i18n('Groupings'), icon: <WorkspacesOutlined fontSize="small" /> },
                  { type: 'Malware-Analysis', link: '/dashboard/analyses/malware_analyses', label: t_i18n('Malware analyses'), icon: <BiotechOutlined fontSize="small" /> },
                  { type: 'Security-Coverage', link: '/dashboard/analyses/security_coverages', label: t_i18n('Security coverages'), icon: <SecurityOutlined fontSize="small" /> },
                  { type: 'Note', link: '/dashboard/analyses/notes', label: t_i18n('Notes'), icon: <SubjectOutlined fontSize="small" /> },
                  { type: 'External-Reference', link: '/dashboard/analyses/external_references', label: t_i18n('External references'), icon: <LocalOfferOutlined fontSize="small" /> },
                ]}
              />
            )}

            {!hideCases && (
              <LeftBarItem
                {...itemProps}
                id="cases"
                icon={<CasesOutlined />}
                label={t_i18n('Cases')}
                link="/dashboard/cases"
                subItems={[
                  { type: 'Case-Incident', link: '/dashboard/cases/incidents', label: t_i18n('Incident responses'), icon: <BriefcaseEyeOutline fontSize="small" /> },
                  { type: 'Case-Rfi', link: '/dashboard/cases/rfis', label: t_i18n('Requests for information'), icon: <BriefcaseSearchOutline fontSize="small" /> },
                  { type: 'Case-Rft', link: '/dashboard/cases/rfts', label: t_i18n('Requests for takedown'), icon: <BriefcaseRemoveOutline fontSize="small" /> },
                  { type: 'Task', link: '/dashboard/cases/tasks', label: t_i18n('Tasks'), icon: <TaskAltOutlined fontSize="small" /> },
                  { type: 'Feedback', link: '/dashboard/cases/feedbacks', label: t_i18n('Feedbacks'), icon: <BriefcaseEditOutline fontSize="small" /> },
                ]}
              />
            )}

            {!hideEvents && (
              <LeftBarItem
                {...itemProps}
                id="events"
                icon={<Timetable />}
                label={t_i18n('Events')}
                link="/dashboard/events"
                subItems={[
                  { type: 'Incident', link: '/dashboard/events/incidents', label: t_i18n('Incidents'), icon: <Fire fontSize="small" /> },
                  { type: 'stix-sighting-relationship', link: '/dashboard/events/sightings', label: t_i18n('Sightings'), icon: <VisibilityOutlined fontSize="small" /> },
                  { type: 'Observed-Data', link: '/dashboard/events/observed_data', label: t_i18n('Observed datas'), icon: <WifiTetheringOutlined fontSize="small" /> },
                ]}
              />
            )}

            {!hideObservations && (
              <LeftBarItem
                {...itemProps}
                id="observations"
                icon={<Binoculars />}
                label={t_i18n('Observations')}
                link="/dashboard/observations"
                subItems={[
                  { type: 'Stix-Cyber-Observable', link: '/dashboard/observations/observables', label: t_i18n('Observables'), icon: <HexagonOutline fontSize="small" /> },
                  { type: 'Artifact', link: '/dashboard/observations/artifacts', label: t_i18n('Artifacts'), icon: <ArchiveOutline fontSize="small" /> },
                  { type: 'Indicator', link: '/dashboard/observations/indicators', label: t_i18n('Indicators'), icon: <ShieldSearch fontSize="small" /> },
                  { type: 'Infrastructure', link: '/dashboard/observations/infrastructures', label: t_i18n('Infrastructures'), icon: <ServerNetwork fontSize="small" /> },
                ]}
              />
            )}
          </MenuList>

          <Separator />

          <MenuList component="nav">
            {!hideThreats && (
              <LeftBarItem
                {...itemProps}
                id="threats"
                icon={<FlaskOutline />}
                label={t_i18n('Threats')}
                link="/dashboard/threats"
                subItems={[
                  { type: 'Threat-Actor-Group', link: '/dashboard/threats/threat_actors_group', label: t_i18n('Threat actors (group)'), icon: <AccountMultipleOutline fontSize="small" /> },
                  {
                    type: 'Threat-Actor-Individual',
                    link: '/dashboard/threats/threat_actors_individual',
                    label: 'Threat actors (individual)',
                    icon: <LaptopAccount fontSize="small" />,
                  },
                  { type: 'Intrusion-Set', link: '/dashboard/threats/intrusion_sets', label: t_i18n('Intrusion sets'), icon: <DiamondOutlined fontSize="small" /> },
                  { type: 'Campaign', link: '/dashboard/threats/campaigns', label: t_i18n('Campaigns'), icon: <ChessKnight fontSize="small" /> },
                ]}
              />
            )}

            {!hideArsenal && (
              <LeftBarItem
                {...itemProps}
                id="arsenal"
                icon={<LayersOutlined />}
                label={t_i18n('Arsenal')}
                link="/dashboard/arsenal"
                subItems={[
                  { type: 'Malware', link: '/dashboard/arsenal/malwares', label: t_i18n('Malwares'), icon: <Biohazard fontSize="small" /> },
                  { type: 'Channel', link: '/dashboard/arsenal/channels', label: t_i18n('Channels'), icon: <SurroundSoundOutlined fontSize="small" /> },
                  { type: 'Tool', link: '/dashboard/arsenal/tools', label: t_i18n('Tools'), icon: <WebAssetOutlined fontSize="small" /> },
                  { type: 'Vulnerability', link: '/dashboard/arsenal/vulnerabilities', label: t_i18n('Vulnerabilities'), icon: <BugReportOutlined fontSize="small" /> },
                ]}
              />
            )}

            {!hideTechniques && (
              <LeftBarItem
                {...itemProps}
                id="techniques"
                icon={<ConstructionOutlined />}
                label={t_i18n('Techniques')}
                link="/dashboard/techniques"
                subItems={[
                  { type: 'Attack-Pattern', link: '/dashboard/techniques/attack_patterns', label: t_i18n('Attack patterns'), icon: <LockPattern fontSize="small" /> },
                  { type: 'Narrative', link: '/dashboard/techniques/narratives', label: t_i18n('Narratives'), icon: <SpeakerNotesOutlined fontSize="small" /> },
                  { type: 'Course-Of-Action', link: '/dashboard/techniques/courses_of_action', label: t_i18n('Courses of action'), icon: <ProgressWrench fontSize="small" /> },
                  { type: 'Data-Component', link: '/dashboard/techniques/data_components', label: t_i18n('Data components'), icon: <SourceOutlined fontSize="small" /> },
                  { type: 'Data-Source', link: '/dashboard/techniques/data_sources', label: t_i18n('Data sources'), icon: <StreamOutlined fontSize="small" /> },
                ]}
              />
            )}

            {!hideEntities && (
              <LeftBarItem
                {...itemProps}
                id="entities"
                icon={<FolderTableOutline />}
                label={t_i18n('Entities')}
                link="/dashboard/entities"
                subItems={
                  [
                    { type: 'Sector', link: '/dashboard/entities/sectors', label: t_i18n('Sectors'), icon: <DomainOutlined fontSize="small" /> },
                    { type: 'Event', link: '/dashboard/entities/events', label: t_i18n('Events'), icon: <EventOutlined fontSize="small" /> },
                    { type: 'Organization', link: '/dashboard/entities/organizations', label: t_i18n('Organizations'), icon: <AccountBalanceOutlined fontSize="small" /> },
                    { type: 'SecurityPlatform', link: '/dashboard/entities/security_platforms', label: t_i18n('Security platforms'), icon: <SecurityOutlined fontSize="small" /> },
                    { type: 'System', link: '/dashboard/entities/systems', label: t_i18n('Systems'), icon: <StorageOutlined fontSize="small" /> },
                    { type: 'Individual', link: '/dashboard/entities/individuals', label: t_i18n('Individuals'), icon: <PersonOutlined fontSize="small" /> },
                  ]
                }
              />
            )}

            {!hideLocations && (
              <LeftBarItem
                {...itemProps}
                id="locations"
                icon={<GlobeModel />}
                label={t_i18n('Locations')}
                link="/dashboard/locations"
                subItems={[
                  { type: 'Region', link: '/dashboard/locations/regions', label: t_i18n('Regions'), icon: <PublicOutlined fontSize="small" /> },
                  { type: 'Country', link: '/dashboard/locations/countries', label: t_i18n('Countries'), icon: <FlagOutlined fontSize="small" /> },
                  { type: 'Administrative-Area', link: '/dashboard/locations/administrative_areas', label: t_i18n('Administrative areas'), icon: <MapOutlined fontSize="small" /> },
                  { type: 'City', link: '/dashboard/locations/cities', label: t_i18n('Cities'), icon: <CityVariantOutline fontSize="small" /> },
                  { type: 'Position', link: '/dashboard/locations/positions', label: t_i18n('Positions'), icon: <PlaceOutlined fontSize="small" /> },
                ]}
              />
            )}
          </MenuList>
        </Security>

        <Security needs={[MODULES, KNOWLEDGE, TAXIIAPI, CSVMAPPERS, INGESTION]}>
          <Separator />

          <MenuList component="nav">
            <Security needs={[MODULES, KNOWLEDGE, TAXIIAPI, CSVMAPPERS, INGESTION]}>
              <LeftBarItem
                {...itemProps}
                id="data"
                icon={<Database />}
                label={t_i18n('Data')}
                link="/dashboard/data"
                subItems={[
                  { granted: isGrantedToKnowledge, link: '/dashboard/data/entities', label: t_i18n('Entities') },
                  { granted: isGrantedToKnowledge, link: '/dashboard/data/relationships', label: t_i18n('Relationships') },
                  { granted: isGrantedToIngestion && !draftContext, link: '/dashboard/data/ingestion', label: t_i18n('Ingestion') },
                  { granted: isGrantedToImport && !draftContext, link: '/dashboard/data/import', label: t_i18n('Import') },
                  { granted: isGrantedToProcessing && !draftContext, link: '/dashboard/data/processing', label: t_i18n('Processing') },
                  { granted: isGrantedToSharing && !draftContext, link: '/dashboard/data/sharing', label: t_i18n('Data sharing') },
                  { granted: isGrantedToManage && !draftContext, link: '/dashboard/data/restriction', label: t_i18n('Restriction') },
                ]}
              />
            </Security>

            {
              isTrashEnable() && (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  {!draftContext && (
                    <LeftBarItem
                      {...itemProps}
                      id="trash"
                      icon={<DeleteOutlined />}
                      label={t_i18n('Trash')}
                      link="/dashboard/trash"
                    />
                  )}
                </Security>
              )
            }
          </MenuList>
        </Security>

        <Security needs={[
          VIRTUAL_ORGANIZATION_ADMIN,
          SETTINGS_SETPARAMETERS,
          SETTINGS_SETACCESSES,
          SETTINGS_SETMARKINGS,
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
          <Separator />
          {!draftContext && (
            <MenuList component="nav" style={{ marginBottom: 48 }}>
              <LeftBarItem
                {...itemProps}
                id="settings"
                icon={<CogOutline />}
                label={t_i18n('Settings')}
                link="/dashboard/settings"
                subItems={[
                  { granted: isGrantedToParameters, link: '/dashboard/settings', label: t_i18n('Parameters'), exact: true },
                  { granted: isGrantedToSecurity || isOrganizationAdmin, link: '/dashboard/settings/accesses', label: t_i18n('Security') },
                  { granted: isGrantedToCustomization, link: '/dashboard/settings/customization', label: t_i18n('Customization') },
                  { granted: isGrantedToTaxonomies, link: '/dashboard/settings/vocabularies', label: t_i18n('Taxonomies') },
                  { granted: isGrantedToAudit, link: '/dashboard/settings/activity', label: t_i18n('Activity') },
                  { granted: isGrantedToFileIndexing, link: '/dashboard/settings/file_indexing', label: t_i18n('File indexing') },
                  { granted: isGrantedToExperience, link: '/dashboard/settings/experience', label: t_i18n('Filigran Experience') },
                ]}
              />
            </MenuList>
          )}
        </Security>
      </div>

      {/** Bottom **/}
      <div
        style={{
          flexShrink: 0,
          borderRight: theme.palette.mode === 'dark'
            ? '1px solid rgba(255, 255, 255, 0.12)'
            : '1px solid rgba(0, 0, 0, 0.12)',
          background: theme.palette.background.paper,
          width: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH,
        }}
      >
        <MenuList
          sx={{
            display: 'flex',
            flexDirection: 'column',
            gap: 2,
          }}
        >
          <LeftBarItem
            {...itemProps}
            icon={navOpen ? <ChevronLeft /> : <ChevronRight />}
            label={t_i18n('Collapse')}
            onClick={handleToggle}
          />
          <Stack direction="row" alignItems="center" gap={0.5} paddingLeft={2.5} marginBottom={1}>
            {
              navOpen && (
                <Typography
                  component="span"
                  sx={{
                    fontFamily: 'IBM Plex Sans',
                    fontSize: '10px',
                    lineHeight: '16px',
                    opacity: 0.8,
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
        </MenuList>
      </div>
    </Drawer>
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
