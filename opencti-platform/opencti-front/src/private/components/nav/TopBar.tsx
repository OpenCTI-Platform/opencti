import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import { useHistory } from 'react-router-dom';
import { Badge } from '@mui/material';
import { Link, useLocation } from 'react-router-dom-v5-compat';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import IconButton from '@mui/material/IconButton';
import { AccountCircleOutlined, BiotechOutlined, ContentPasteSearchOutlined, ExploreOutlined, InsertChartOutlined, NotificationsOutlined } from '@mui/icons-material';
import { DatabaseCogOutline } from 'mdi-material-ui';
import Menu from '@mui/material/Menu';
import Divider from '@mui/material/Divider';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { usePage } from 'use-analytics';
import { useFormatter } from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import TopMenuDashboard from './TopMenuDashboard';
import TopMenuSearch from './TopMenuSearch';
import TopMenuAnalyses from './TopMenuAnalyses';
import TopMenuOpinion from './TopMenuOpinion';
import TopMenuEvents from './TopMenuEvents';
import TopMenuObservations from './TopMenuObservations';
import TopMenuThreats from './TopMenuThreats';
import TopMenuArsenal from './TopMenuArsenal';
import TopMenuEntities from './TopMenuEntities';
import TopMenuData from './TopMenuData';
import TopMenuSettings from './TopMenuSettings';
import TopMenuTechniques from './TopMenuTechniques';
import { APP_BASE_PATH, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import TopMenuWorkspacesDashboards from './TopMenuWorkspacesDashboards';
import TopMenuWorkspacesInvestigations from './TopMenuWorkspacesInvestigations';
import TopMenuImport from './TopMenuImport';
import TopMenuLocation from './TopMenuLocation';
import FeedbackCreation from '../cases/feedbacks/FeedbackCreation';
import TopMenuCases from './TopMenuCases';
import type { Theme } from '../../../components/Theme';
import { EXPLORE, KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from '../../../utils/hooks/useGranted';
import TopMenuProfile from '../profile/TopMenuProfile';
import TopMenuNotifications from '../profile/TopMenuNotifications';
import { TopBarQuery } from './__generated__/TopBarQuery.graphql';
import { TopBarNotificationNumberSubscription$data } from './__generated__/TopBarNotificationNumberSubscription.graphql';
import useAuth from '../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { decodeSearchKeyword, handleSearchByKeyword } from '../../../utils/SearchUtils';

const useStyles = makeStyles<Theme>((theme) => ({
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    background: 0,
    backgroundColor: theme.palette.background.nav,
    paddingTop: theme.spacing(0.2),
  },
  logoContainer: {
    margin: '2px 0 0 -8px',
  },
  logo: {
    cursor: 'pointer',
    height: 35,
  },
  logoCollapsed: {
    cursor: 'pointer',
    height: 35,
    marginRight: 4,
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

const topBarNotificationNumberSubscription = graphql`
  subscription TopBarNotificationNumberSubscription {
    notificationsNumber {
      count
    }
  }
`;

interface TopBarProps {
  queryRef: PreloadedQuery<TopBarQuery>;
}

const topBarQuery = graphql`
  query TopBarQuery {
    myUnreadNotificationsCount
  }
`;

const routes = {
  // ME
  '/dashboard/profile/me': () => <TopMenuProfile/>,
  '/dashboard/profile/': () => <TopMenuNotifications/>,
  '/dashboard/cases': () => <TopMenuCases/>,
  '/dashboard/analyses/opinions/': (id: string) => <TopMenuOpinion id={id}/>,
  '/dashboard/analyses': () => <TopMenuAnalyses/>,
  '/dashboard/events': () => <TopMenuEvents/>,
  '/dashboard/observations': () => <TopMenuObservations/>,
  '/dashboard/threats': () => <TopMenuThreats/>,
  '/dashboard/arsenal': () => <TopMenuArsenal/>,
  '/dashboard/entities': () => <TopMenuEntities/>,
  '/dashboard/locations': () => <TopMenuLocation/>,
  '/dashboard/techniques': () => <TopMenuTechniques/>,
  '/dashboard/data': () => <TopMenuData/>,
  '/dashboard/settings': () => <TopMenuSettings/>,
  '/dashboard/workspaces/dashboards': () => <TopMenuWorkspacesDashboards/>,
  '/dashboard/workspaces/investigations': () => (
    <TopMenuWorkspacesInvestigations/>
  ),
  '/dashboard/search': () => <TopMenuSearch/>,
  '/dashboard/import': () => <TopMenuImport/>,
  '/dashboard': () => <TopMenuDashboard/>,
};

const TopBarComponent: FunctionComponent<TopBarProps> = ({
  queryRef,
}) => {
  const theme = useTheme<Theme>();
  const history = useHistory();
  const location = useLocation();
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const [notificationsNumber, setNotificationsNumber] = useState<null | number>(
    null,
  );
  const data = usePreloadedQuery(topBarQuery, queryRef);
  const page = usePage();
  const handleNewNotificationsNumber = (
    response: TopBarNotificationNumberSubscription$data | null | undefined | unknown,
  ) => {
    const notificationNumber = response ? (response as TopBarNotificationNumberSubscription$data).notificationsNumber?.count : null;
    return setNotificationsNumber(notificationNumber ?? null);
  };
  const isNewNotification = notificationsNumber !== null
    ? notificationsNumber > 0
    : (data.myUnreadNotificationsCount ?? 0) > 0;
  const subConfig = useMemo(
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
  useEffect(() => {
    page();
  }, [location.pathname]);
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
    handleSearchByKeyword(searchKeyword, 'knowledge', history);
  };
  const handleOpenDrawer = () => {
    setOpenDrawer(true);
    handleCloseMenu();
  };
  const handleCloseDrawer = () => {
    setOpenDrawer(false);
    handleCloseMenu();
  };

  // global search keyword
  const keyword = decodeSearchKeyword(location.pathname.match(/(?:\/dashboard\/search\/(?:knowledge|files)\/(.*))/)?.[1] ?? '');

  const extractId = (path = '') => location.pathname.split(path)[1].split('/')[0];
  const [routePath, routeFn] = Object.entries(routes).find(([path]) => location.pathname.includes(path))
  ?? [];
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
                  placeholder={`${t_i18n('Search the platform')}...`}
                />
                <Tooltip title={t_i18n('Advanced search')}>
                  <IconButton
                    component={Link}
                    to="/dashboard/search"
                    color={
                      location.pathname.includes('/dashboard/search')
                      && !location.pathname.includes('/dashboard/search_bulk')
                        ? 'secondary'
                        : 'default'
                    }
                    size={'medium'}
                  >
                    <BiotechOutlined fontSize={'medium'}/>
                  </IconButton>
                </Tooltip>
                <Tooltip title={t_i18n('Bulk search')}>
                  <IconButton
                    component={Link}
                    to="/dashboard/search_bulk"
                    color={
                      location.pathname.includes('/dashboard/search_bulk')
                        ? 'primary'
                        : 'default'
                    }
                    size="medium"
                  >
                    <ContentPasteSearchOutlined fontSize="medium"/>
                  </IconButton>
                </Tooltip>
              </div>
              <Divider className={classes.divider} orientation="vertical"/>
            </React.Fragment>
          </Security>
          <div className={classes.barRightContainer}>
            <Security needs={[EXPLORE]}>
              <React.Fragment>
                <Tooltip title={t_i18n('Custom dashboards')}>
                  <IconButton
                    component={Link}
                    to="/dashboard/workspaces/dashboards"
                    color={
                      location.pathname.includes(
                        '/dashboard/workspaces/dashboards',
                      )
                        ? 'primary'
                        : 'default'
                    }
                    size="medium"
                  >
                    <InsertChartOutlined fontSize="medium"/>
                  </IconButton>
                </Tooltip>
                <Tooltip title={t_i18n('Investigations')}>
                  <IconButton
                    component={Link}
                    to="/dashboard/workspaces/investigations"
                    color={
                      location.pathname.includes(
                        '/dashboard/workspaces/investigations',
                      )
                        ? 'primary'
                        : 'default'
                    }
                    size="medium"
                  >
                    <ExploreOutlined fontSize="medium"/>
                  </IconButton>
                </Tooltip>
              </React.Fragment>
            </Security>
            <Security needs={[KNOWLEDGE_KNASKIMPORT]}>
              <Tooltip title={t_i18n('Data import and analyst workbenches')}>
                <IconButton
                  component={Link}
                  to="/dashboard/import"
                  color={
                    location.pathname.includes('/dashboard/import')
                      ? 'primary'
                      : 'default'
                  }
                  size="medium"
                >
                  <DatabaseCogOutline fontSize="medium"/>
                </IconButton>
              </Tooltip>
            </Security>
            <Security needs={[KNOWLEDGE]}>
              <Tooltip title={t_i18n('Notifications and triggers')}>
                <IconButton
                  size="medium"
                  classes={{ root: classes.button }}
                  aria-haspopup="true"
                  component={Link}
                  to="/dashboard/profile/notifications"
                  color={
                    [
                      '/dashboard/profile/notifications',
                      '/dashboard/profile/triggers',
                    ].includes(location.pathname)
                      ? 'primary'
                      : 'default'
                  }
                >
                  <Badge
                    color="secondary"
                    variant="dot"
                    invisible={!isNewNotification}
                  >
                    <NotificationsOutlined fontSize="medium"/>
                  </Badge>
                </IconButton>
              </Tooltip>
            </Security>
            <IconButton
              size="medium"
              classes={{ root: classes.button }}
              aria-owns={menuOpen.open ? 'menu-appbar' : undefined}
              aria-haspopup="true"
              aria-label={t_i18n('Profile')}
              id="profile-menu-button"
              onClick={handleOpenMenu}
              color={
                location.pathname === '/dashboard/profile/me'
                  ? 'primary'
                  : 'default'
              }
            >
              <AccountCircleOutlined fontSize="medium"/>
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
                {t_i18n('Profile')}
              </MenuItem>
              <MenuItem onClick={handleOpenDrawer}>{t_i18n('Feedback')}</MenuItem>
              <MenuItem
                component="a"
                href={`${APP_BASE_PATH}/logout`}
                rel="noreferrer"
              >
                {t_i18n('Logout')}
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

const TopBar: FunctionComponent<Omit<TopBarProps, 'queryRef'>> = () => {
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
          <TopBarComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default TopBar;
