import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { Badge } from '@mui/material';
import { Link, useLocation } from 'react-router-dom-v5-compat';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import IconButton from '@mui/material/IconButton';
import { AccountCircleOutlined, ContentPasteSearchOutlined, ExploreOutlined, InsertChartOutlined, NotificationsOutlined } from '@mui/icons-material';
import { DatabaseCogOutline } from 'mdi-material-ui';
import Menu from '@mui/material/Menu';
import Divider from '@mui/material/Divider';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { useFormatter } from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import TopMenuDashboard from './TopMenuDashboard';
import TopMenuSearch from './TopMenuSearch';
import TopMenuAnalyses from './TopMenuAnalyses';
import TopMenuReport from './TopMenuReport';
import TopMenuNote from './TopMenuNote';
import TopMenuOpinion from './TopMenuOpinion';
import TopMenuGrouping from './TopMenuGrouping';
import TopMenuExternalReference from './TopMenuExternalReference';
import TopMenuEvents from './TopMenuEvents';
import TopMenuIncident from './TopMenuIncident';
import TopMenuObservedData from './TopMenuObservedData';
import TopMenuObservations from './TopMenuObservations';
import TopMenuIndicator from './TopMenuIndicator';
import TopMenuInfrastructure from './TopMenuInfrastructure';
import TopMenuStixCyberObservable from './TopMenuStixCyberObservable';
import TopMenuArtifact from './TopMenuArtifact';
import TopMenuThreats from './TopMenuThreats';
import TopMenuThreatActorGroup from './TopMenuThreatActorGroup';
import TopMenuIntrusionSet from './TopMenuIntrusionSet';
import TopMenuCampaign from './TopMenuCampaign';
import TopMenuArsenal from './TopMenuArsenal';
import TopMenuMalware from './TopMenuMalware';
import TopMenuTool from './TopMenuTool';
import TopMenuAttackPattern from './TopMenuAttackPattern';
import TopMenuVulnerability from './TopMenuVulnerability';
import TopMenuEntities from './TopMenuEntities';
import TopMenuSector from './TopMenuSector';
import TopMenuSystem from './TopMenuSystem';
import TopMenuOrganization from './TopMenuOrganization';
import TopMenuIndividual from './TopMenuIndividual';
import TopMenuRegion from './TopMenuRegion';
import TopMenuCountry from './TopMenuCountry';
import TopMenuAdministrativeArea from './TopMenuAdministrativeArea';
import TopMenuCity from './TopMenuCity';
import TopMenuPosition from './TopMenuPosition';
import TopMenuData from './TopMenuData';
import TopMenuSettings from './TopMenuSettings';
import TopMenuTechniques from './TopMenuTechniques';
import { commitMutation, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import TopMenuCourseOfAction from './TopMenuCourseOfAction';
import TopMenuWorkspacesDashboards from './TopMenuWorkspacesDashboards';
import TopMenuWorkspacesInvestigations from './TopMenuWorkspacesInvestigations';
import Filters from '../common/lists/Filters';
import TopMenuChannel from './TopMenuChannel';
import TopMenuNarrative from './TopMenuNarrative';
import TopMenuEvent from './TopMenuEvent';
import TopMenuImport from './TopMenuImport';
import TopMenuLocation from './TopMenuLocation';
import TopMenuDataComponent from './TopMenuDataComponent';
import TopMenuDataSource from './TopMenuDataSource';
import TopMenuCaseIncident from './TopMenuCaseIncident';
import TopMenuCaseFeedback from './TopMenuCaseFeedback';
import FeedbackCreation from '../cases/feedbacks/FeedbackCreation';
import TopMenuCases from './TopMenuCases';
import TopMenuMalwareAnalysis from './TopMenuMalwareAnalysis';
import { Theme } from '../../../components/Theme';
import { EXPLORE, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from '../../../utils/hooks/useGranted';
import TopMenuProfile from '../profile/TopMenuProfile';
import TopMenuNotifications from '../profile/TopMenuNotifications';
import { TopBarQuery } from './__generated__/TopBarQuery.graphql';
import { TopBarNotificationNumberSubscription, TopBarNotificationNumberSubscription$data } from './__generated__/TopBarNotificationNumberSubscription.graphql';
import TopMenuCaseRfi from './TopMenuCaseRfi';
import TopMenuCaseRft from './TopMenuCaseRft';
import TopMenuTask from './TopMenuTask';
import TopMenuAudits from './TopMenuAudits';
import useAuth from '../../../utils/hooks/useAuth';
import TopMenuThreatActorIndividual from './TopMenuThreatActorIndividual';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';

const useStyles = makeStyles<Theme>((theme) => ({
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    background: 0,
    backgroundColor: theme.palette.background.nav,
    paddingTop: theme.spacing(0.2),
  },
  logoContainer: {
    margin: '2px 0 0 -10px',
  },
  logo: {
    cursor: 'pointer',
    height: 35,
  },
  logoCollapsed: {
    cursor: 'pointer',
    height: 35,
    marginRight: 10,
  },
  menuContainer: {
    float: 'left',
    marginLeft: 30,
  },
  barRight: {
    position: 'absolute',
    top: 0,
    right: 13,
    height: '100%',
  },
  barRightContainer: {
    float: 'left',
    height: '100%',
    paddingTop: 12,
  },
  divider: {
    display: 'table-cell',
    height: '100%',
    float: 'left',
    margin: '0 5px 0 5px',
  },
}));

const logoutMutation = graphql`
  mutation TopBarLogoutMutation {
    logout
  }
`;

export const handleLogout = (redirect = '') => {
  function redirectWindow() {
    if (redirect === '' || redirect.length === undefined) window.location.reload();
    else window.location.replace(redirect);
  }

  commitMutation({
    mutation: logoutMutation,
    variables: {},
    onCompleted: redirectWindow,
    updater: undefined,
    optimisticUpdater: undefined,
    optimisticResponse: undefined,
    onError: redirectWindow,
    setSubmitting: undefined,
  });
};

const topBarNotificationNumberSubscription = graphql`
  subscription TopBarNotificationNumberSubscription {
    notificationsNumber {
      count
    }
  }
`;

interface TopBarProps {
  keyword?: string;
  queryRef: PreloadedQuery<TopBarQuery>;
}

const topBarQuery = graphql`
  query TopBarQuery {
    myUnreadNotificationsCount
  }
`;

const routes = {
  // ME
  '/dashboard/profile/me': () => <TopMenuProfile />,
  '/dashboard/profile/': () => <TopMenuNotifications />,
  // CASES
  '/dashboard/cases/feedbacks/': (id: string) => <TopMenuCaseFeedback id={id} />,
  '/dashboard/cases/tasks/': (id: string) => <TopMenuTask id={id} />,
  '/dashboard/cases/rfts/': (id: string) => <TopMenuCaseRft id={id} />,
  '/dashboard/cases/rfis/': (id: string) => <TopMenuCaseRfi id={id} />,
  '/dashboard/cases/incidents/': (id: string) => <TopMenuCaseIncident id={id} />,
  '/dashboard/cases': () => <TopMenuCases />,
  // ANALYSIS
  '/dashboard/analyses/reports/': (id: string) => <TopMenuReport id={id} />,
  '/dashboard/analyses/groupings/': (id: string) => <TopMenuGrouping id={id} />,
  '/dashboard/analyses/malware_analyses/': (id: string) => <TopMenuMalwareAnalysis id={id} />,
  '/dashboard/analyses/notes/': (id: string) => <TopMenuNote id={id} />,
  '/dashboard/analyses/opinions/': (id: string) => <TopMenuOpinion id={id} />,
  '/dashboard/analyses/external_references/': (id: string) => <TopMenuExternalReference id={id} />,
  '/dashboard/analyses': () => <TopMenuAnalyses />,
  // EVENTS
  '/dashboard/events/sightings/': () => <TopMenuEvents />,
  '/dashboard/events/observed_data/': (id: string) => <TopMenuObservedData id={id} />,
  '/dashboard/events/incidents/': (id: string) => <TopMenuIncident id={id} />,
  '/dashboard/events': () => <TopMenuEvents />,
  // OBSERVATIONS
  '/dashboard/observations/indicators/': (id: string) => <TopMenuIndicator id={id} />,
  '/dashboard/observations/infrastructures/': (id: string) => <TopMenuInfrastructure id={id} />,
  '/dashboard/observations/observables/': (id: string) => <TopMenuStixCyberObservable id={id} />,
  '/dashboard/observations/artifacts/': (id: string) => <TopMenuArtifact id={id} />,
  '/dashboard/observations': () => <TopMenuObservations />,
  // THREATS
  '/dashboard/threats/threat_actors_group/': (id: string) => <TopMenuThreatActorGroup id={id} />,
  '/dashboard/threats/threat_actors_individual/': (id: string) => <TopMenuThreatActorIndividual id={id} />,
  '/dashboard/threats/intrusion_sets/': (id: string) => <TopMenuIntrusionSet id={id} />,
  '/dashboard/threats/campaigns/': (id: string) => <TopMenuCampaign id={id} />,
  '/dashboard/threats': () => <TopMenuThreats />,
  // ARSENAL
  '/dashboard/arsenal/malwares/': (id: string) => <TopMenuMalware id={id} />,
  '/dashboard/arsenal/tools/': (id: string) => <TopMenuTool id={id} />,
  '/dashboard/arsenal/channels/': (id: string) => <TopMenuChannel id={id} />,
  '/dashboard/arsenal/vulnerabilities/': (id: string) => <TopMenuVulnerability id={id} />,
  '/dashboard/arsenal': () => <TopMenuArsenal />,
  // ENTITIES
  '/dashboard/entities/sectors/': (id: string) => <TopMenuSector id={id} />,
  '/dashboard/entities/systems/': (id: string) => <TopMenuSystem id={id} />,
  '/dashboard/entities/events/': (id: string) => <TopMenuEvent id={id} />,
  '/dashboard/entities/organizations/': (id: string) => <TopMenuOrganization id={id} />,
  '/dashboard/entities/individuals/': (id: string) => <TopMenuIndividual id={id} />,
  '/dashboard/entities': () => <TopMenuEntities />,
  // LOCATIONS
  '/dashboard/locations/countries/': (id: string) => <TopMenuCountry id={id} />,
  '/dashboard/locations/regions/': (id: string) => <TopMenuRegion id={id} />,
  '/dashboard/locations/administrative_areas/': (id: string) => <TopMenuAdministrativeArea id={id} />,
  '/dashboard/locations/cities/': (id: string) => <TopMenuCity id={id} />,
  '/dashboard/locations/positions/': (id: string) => <TopMenuPosition id={id} />,
  '/dashboard/locations': () => <TopMenuLocation />,
  // TECHNIQUES
  '/dashboard/techniques/attack_patterns/': (id: string) => <TopMenuAttackPattern id={id} />,
  '/dashboard/techniques/narratives/': (id: string) => <TopMenuNarrative id={id} />,
  '/dashboard/techniques/courses_of_action/': (id: string) => <TopMenuCourseOfAction id={id} />,
  '/dashboard/techniques/data_components/': (id: string) => <TopMenuDataComponent id={id} />,
  '/dashboard/techniques/data_sources/': (id: string) => <TopMenuDataSource id={id} />,
  '/dashboard/techniques': () => <TopMenuTechniques />,
  '/dashboard/data': () => <TopMenuData />,
  '/dashboard/activity': () => <TopMenuAudits />,
  '/dashboard/settings': () => <TopMenuSettings />,
  '/dashboard/workspaces/dashboards': () => <TopMenuWorkspacesDashboards />,
  '/dashboard/workspaces/investigations': () => <TopMenuWorkspacesInvestigations />,
  '/dashboard/search': () => <TopMenuSearch />,
  '/dashboard/import': () => <TopMenuImport />,
  '/dashboard': () => <TopMenuDashboard />,
};

const TopBarComponent: FunctionComponent<TopBarProps> = ({
  queryRef,
  keyword,
}) => {
  const theme = useTheme<Theme>();
  const history = useHistory();
  const location = useLocation();
  const classes = useStyles();
  const { t } = useFormatter();
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const [notificationsNumber, setNotificationsNumber] = useState<null | number>(
    null,
  );
  const data = usePreloadedQuery(topBarQuery, queryRef);
  const handleNewNotificationsNumber = (
    response: TopBarNotificationNumberSubscription$data | null | undefined,
  ) => {
    return setNotificationsNumber(response?.notificationsNumber?.count ?? null);
  };
  const isNewNotification = notificationsNumber !== null
    ? notificationsNumber > 0
    : (data.myUnreadNotificationsCount ?? 0) > 0;
  const subConfig = useMemo<GraphQLSubscriptionConfig<TopBarNotificationNumberSubscription>>(
    () => ({
      subscription: topBarNotificationNumberSubscription,
      variables: {},
      onNext: handleNewNotificationsNumber,
    }),
    [topBarNotificationNumberSubscription],
  );
  useSubscription(subConfig);
  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );
  useEffect(() => {
    const sub = MESSAGING$.toggleNav.subscribe({
      next: () => setNavOpen(localStorage.getItem('navOpen') === 'true'),
    });
    return () => {
      sub.unsubscribe();
    };
  });
  const [menuOpen, setMenuOpen] = useState<{
    open: boolean;
    anchorEl: HTMLButtonElement | null;
  }>({ open: false, anchorEl: null });
  const [openDrawer, setOpenDrawer] = useState(false);

  const handleOpenMenu = (
    event: React.MouseEvent<HTMLButtonElement, MouseEvent>,
  ) => {
    event.preventDefault();
    setMenuOpen({ open: true, anchorEl: event.currentTarget });
  };
  const handleCloseMenu = () => {
    setMenuOpen({ open: false, anchorEl: null });
  };
  const handleSearch = (searchKeyword: string) => {
    if (searchKeyword.length > 0) {
      // With need to double encode because of react router.
      // Waiting for history 5.0 integrated to react router.
      const encodeKey = encodeURIComponent(encodeURIComponent(searchKeyword));
      history.push(`/dashboard/search/${encodeKey}`);
    }
  };
  const handleOpenDrawer = () => {
    setOpenDrawer(true);
    handleCloseMenu();
  };
  const handleCloseDrawer = () => {
    setOpenDrawer(false);
    handleCloseMenu();
  };

  const extractId = (path = '') => location.pathname.split(path)[1].split('/')[0];
  const [routePath, routeFn] = Object.entries(routes).find(([path]) => location.pathname.includes(path)) ?? [];
  return (
    <AppBar
      position="fixed"
      className={classes.appBar}
      variant="elevation"
      elevation={1}
    >
      {/* Header and Footer Banners containing classification level of system */}
      <Toolbar
        style={{ marginTop: bannerHeightNumber + settingsMessagesBannerHeight }}
      >
        <div className={classes.logoContainer}>
          <Link to="/dashboard">
            <img
              src={navOpen ? theme.logo : theme.logo_collapsed}
              alt="logo"
              className={navOpen ? classes.logo : classes.logoCollapsed}
            />
          </Link>
        </div>
        <div className={classes.menuContainer}>
          {routeFn?.(extractId(routePath))}
        </div>
        <div className={classes.barRight}>
          <Security needs={[KNOWLEDGE]}>
            <React.Fragment>
              <div className={classes.barRightContainer}>
                <SearchInput
                  onSubmit={handleSearch}
                  keyword={keyword}
                  variant="topBar"
                />
                <Filters
                  variant="dialog"
                  availableFilterKeys={[
                    'entity_type',
                    'labelledBy',
                    'markedBy',
                    'createdBy',
                    'source_reliability',
                    'confidence',
                    'x_opencti_organization_type',
                    'creator',
                    'created_start_date',
                    'created_end_date',
                    'created_at_start_date',
                    'created_at_end_date',
                  ]}
                  disabled={location.pathname.includes('/dashboard/search/')}
                  size={undefined}
                  fontSize={undefined}
                  noDirectFilters={undefined}
                  availableEntityTypes={undefined}
                  availableRelationshipTypes={undefined}
                  allEntityTypes={undefined}
                  handleAddFilter={undefined}
                  handleRemoveFilter={undefined}
                  handleSwitchFilter={undefined}
                  type={undefined}
                  availableRelationFilterTypes={undefined}
                />
                <Tooltip title={t('Bulk search')}>
                  <IconButton
                    component={Link}
                    to="/dashboard/search_bulk"
                    color={
                      location.pathname.includes('/dashboard/search_bulk')
                        ? 'secondary'
                        : 'default'
                    }
                    size="medium"
                  >
                    <ContentPasteSearchOutlined fontSize="medium" />
                  </IconButton>
                </Tooltip>
              </div>
              <Divider className={classes.divider} orientation="vertical" />
            </React.Fragment>
          </Security>
          <div className={classes.barRightContainer}>
            <Security needs={[EXPLORE]}>
              <React.Fragment>
                <Tooltip title={t('Custom dashboards')}>
                  <IconButton
                    component={Link}
                    to="/dashboard/workspaces/dashboards"
                    color={
                      location.pathname.includes(
                        '/dashboard/workspaces/dashboards',
                      )
                        ? 'secondary'
                        : 'default'
                    }
                    size="medium"
                  >
                    <InsertChartOutlined fontSize="medium" />
                  </IconButton>
                </Tooltip>
                <Tooltip title={t('Investigations')}>
                  <IconButton
                    component={Link}
                    to="/dashboard/workspaces/investigations"
                    color={
                      location.pathname.includes(
                        '/dashboard/workspaces/investigations',
                      )
                        ? 'secondary'
                        : 'default'
                    }
                    size="medium"
                  >
                    <ExploreOutlined fontSize="medium" />
                  </IconButton>
                </Tooltip>
              </React.Fragment>
            </Security>
            <Security needs={[KNOWLEDGE_KNASKIMPORT]}>
              <Tooltip title={t('Data import and analyst workbenches')}>
                <IconButton
                  component={Link}
                  to="/dashboard/import"
                  color={
                    location.pathname.includes('/dashboard/import')
                      ? 'secondary'
                      : 'default'
                  }
                  size="medium"
                >
                  <DatabaseCogOutline fontSize="medium" />
                </IconButton>
              </Tooltip>
            </Security>
            <Security needs={[KNOWLEDGE]}>
              <Tooltip title={t('Notifications and triggers')}>
                <IconButton
                  size="medium"
                  classes={{ root: classes.button }}
                  aria-haspopup="true"
                  component={Link}
                  to="/dashboard/profile/notifications"
                  color={
                    ['/dashboard/profile/notifications', '/dashboard/profile/triggers'].includes(location.pathname)
                      ? 'secondary'
                      : 'default'
                  }
                >
                  <Badge
                    color="warning"
                    variant="dot"
                    invisible={!isNewNotification}
                  >
                    <NotificationsOutlined fontSize="medium" />
                  </Badge>
                </IconButton>
              </Tooltip>
            </Security>
            <IconButton
              size="medium"
              classes={{ root: classes.button }}
              aria-owns={menuOpen.open ? 'menu-appbar' : undefined}
              aria-haspopup="true"
              id="profile-menu-button"
              onClick={handleOpenMenu}
              color={
                location.pathname === '/dashboard/profile/me'
                  ? 'secondary'
                  : 'default'
              }
            >
              <AccountCircleOutlined fontSize="medium" />
            </IconButton>
            <Menu
              id="menu-appbar"
              anchorEl={menuOpen.anchorEl}
              open={menuOpen.open}
              onClose={handleCloseMenu}
            >
              <MenuItem
                component={Link}
                to="/dashboard/profile"
                onClick={handleCloseMenu}
              >
                {t('Profile')}
              </MenuItem>
              <MenuItem onClick={handleOpenDrawer}>{t('Feedback')}</MenuItem>
              <MenuItem id="logout-button" onClick={() => handleLogout()}>
                {t('Logout')}
              </MenuItem>
            </Menu>
          </div>
        </div>
      </Toolbar>
      <FeedbackCreation
        openDrawer={openDrawer}
        handleCloseDrawer={handleCloseDrawer}
      />
    </AppBar>
  );
};

const TopBar: FunctionComponent<Omit<TopBarProps, 'queryRef'>> = ({ keyword }) => {
  const queryRef = useQueryLoading<TopBarQuery>(topBarQuery, {});
  const classes = useStyles();
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={
            <AppBar
              position="fixed"
              className={classes.appBar}
              variant="elevation"
              elevation={1}
            />
          }
        >
          <TopBarComponent queryRef={queryRef} keyword={keyword} />
        </React.Suspense>
      )}
    </>
  );
};

export default TopBar;
