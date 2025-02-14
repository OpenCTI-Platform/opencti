import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Badge } from '@mui/material';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import IconButton from '@mui/material/IconButton';
import { AccountCircleOutlined, AlarmOnOutlined, AppsOutlined, NotificationsOutlined } from '@mui/icons-material';
import Menu from '@mui/material/Menu';
import Grid from '@mui/material/Grid';
import MenuItem from '@mui/material/MenuItem';
import Tooltip from '@mui/material/Tooltip';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import { usePage } from 'use-analytics';
import Popover from '@mui/material/Popover';
import Box from '@mui/material/Box';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/LeftBar';
import DraftContextBanner from '@components/drafts/DraftContextBanner';
import { getDraftModeColor } from '@components/common/draft/DraftChip';
import { TopBarAskAINLQMutation, TopBarAskAINLQMutation$data } from '@components/nav/__generated__/TopBarAskAINLQMutation.graphql';
import { useFormatter } from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import { APP_BASE_PATH, fileUri, MESSAGING$ } from '../../../relay/environment';
import Security from '../../../utils/Security';
import FeedbackCreation from '../cases/feedbacks/FeedbackCreation';
import type { Theme } from '../../../components/Theme';
import useGranted, { KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from '../../../utils/hooks/useGranted';
import { TopBarQuery } from './__generated__/TopBarQuery.graphql';
import { TopBarNotificationNumberSubscription$data } from './__generated__/TopBarNotificationNumberSubscription.graphql';
import useAuth from '../../../utils/hooks/useAuth';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { decodeSearchKeyword, handleSearchByFilter, handleSearchByKeyword } from '../../../utils/SearchUtils';
import octiDark from '../../../static/images/xtm/octi_dark.png';
import octiLight from '../../../static/images/xtm/octi_light.png';
import obasDark from '../../../static/images/xtm/obas_dark.png';
import obasLight from '../../../static/images/xtm/obas_light.png';
import xtmhubDark from '../../../static/images/xtm/xtm_hub_dark.png';
import xtmhubLight from '../../../static/images/xtm/xtm_hub_light.png';
import { isNotEmptyField } from '../../../utils/utils';
import ItemBoolean from '../../../components/ItemBoolean';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { RelayError } from '../../../relay/relayTypes';
import { isFilterGroupNotEmpty } from '../../../utils/filters/filtersUtils';
import UploadImport from '../../../components/UploadImport';
import { deserializeThemeManifest } from '../settings/themes/ThemeType';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    background: 0,
    backgroundColor: theme.palette.background.nav,
    paddingTop: theme.spacing(0.2),
    borderLeft: 0,
    borderRight: 0,
    borderTop: 0,
    color: theme.palette.text?.primary,
  },
  logoContainer: {
    marginTop: theme.spacing(0.2),
    paddingLeft: theme.spacing(1),
    minWidth: SMALL_BAR_WIDTH,
  },
  logo: {
    cursor: 'pointer',
    height: 35,
    marginRight: 3,
  },
  logoCollapsed: {
    cursor: 'pointer',
    height: 35,
    marginRight: 4,
  },
  barRight: {
    marginRight: theme.spacing(2),
    height: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'end',
    marginLeft: 'auto',
  },
  barRightContainer: {
    float: 'left',
  },
  subtitle: {
    color: theme.palette.text?.secondary,
    fontSize: '15px',
    marginBottom: 20,
  },
  xtmItem: {
    display: 'block',
    color: theme.palette.text?.primary,
    textAlign: 'center',
    padding: '15px 0 10px 0',
    borderRadius: 4,
    '&:hover': {
      backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)',
    },
  },
  xtmItemCurrent: {
    display: 'block',
    color: theme.palette.text?.primary,
    textAlign: 'center',
    cursor: 'normal',
    padding: '15px 0 10px 0',
    backgroundColor: theme.palette.mode === 'dark' ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.05)',
    borderRadius: 4,
  },
  product: {
    margin: '5px auto 0 auto',
    textAlign: 'center',
    fontSize: 15,
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
    settings {
      platform_theme
    }
    themes {
      edges {
        node {
          name
          manifest
        }
      }
    }
  }
`;

const topBarAskAINLQMutation = graphql`
  mutation TopBarAskAINLQMutation($search: String!) {
    aiNLQ(search: $search) {
      filters
      notResolvedValues
    }
  }
`;

const TopBarComponent: FunctionComponent<TopBarProps> = ({
  queryRef,
}) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const location = useLocation();
  const isEnterpriseEdition = useEnterpriseEdition();
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const {
    bannerSettings: { bannerHeightNumber },
    settings: { platform_openbas_url: openBASUrl, platform_enterprise_edition: ee, platform_xtmhub_url: xtmhubUrl },
  } = useAuth();
  const draftContext = useDraftContext();
  const hasKnowledgeAccess = useGranted([KNOWLEDGE]);
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const [notificationsNumber, setNotificationsNumber] = useState<null | number>(
    null,
  );
  const [isNLQLoading, setIsNLQLoading] = useState(false);
  const [commitMutationNLQ] = useApiMutation<TopBarAskAINLQMutation>(topBarAskAINLQMutation);

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
  const { themes } = data;
  const current_theme = data.settings?.platform_theme;
  const themeLogo = themes?.edges?.filter((node) => !!node)
    .map(({ node }) => ({
      name: node.name,
      ...deserializeThemeManifest(node.manifest),
    }))
    .filter(({ name }) => name === current_theme)?.[0];
  const fallbackLogo = navOpen
    ? theme.logo
    : theme.logo_collapsed;
  let topBarLogo: string | undefined | null;
  if (themeLogo) {
    topBarLogo = navOpen
      ? themeLogo.theme_logo
      : themeLogo.theme_logo_collapsed;
  }
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
  const [xtmOpen, setXtmOpen] = useState<{
    open: boolean;
    anchorEl: HTMLButtonElement | null;
  }>({ open: false, anchorEl: null });
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
  const handleOpenXtm = (
    event: React.MouseEvent<HTMLButtonElement, MouseEvent>,
  ) => {
    event.preventDefault();
    setXtmOpen({ open: true, anchorEl: event.currentTarget });
  };
  const handleCloseXtm = () => {
    setXtmOpen({ open: false, anchorEl: null });
  };
  const handleSearch = (searchKeyword: string, askAI = false) => {
    if (askAI && isEnterpriseEdition) {
      setIsNLQLoading(true);
      commitMutationNLQ({
        variables: {
          search: searchKeyword,
        },
        onCompleted: (response: TopBarAskAINLQMutation$data) => {
          setIsNLQLoading(false);
          const notResolvedValues = response.aiNLQ?.notResolvedValues ?? [];
          const filters = response.aiNLQ?.filters;
          if (notResolvedValues.length > 0) {
            MESSAGING$.notifyNLQ(`${t_i18n('Some entities you mentioned have not been found in the platform')}: ${notResolvedValues}`);
          } else if (!filters || !isFilterGroupNotEmpty(JSON.parse(filters))) {
            MESSAGING$.notifyNLQ(t_i18n('The NLQ model didn\'t find filters corresponding to your question'));
          }
          handleSearchByFilter(searchKeyword, 'nlq', navigate, response.aiNLQ?.filters);
        },
        onError: (error: Error) => {
          setIsNLQLoading(false);
          const { errors } = (error as unknown as RelayError).res;
          MESSAGING$.notifyError(errors.at(0)?.message);
        },
      });
    } else {
      handleSearchByKeyword(searchKeyword, 'knowledge', navigate);
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
  // global search keyword
  const keyword = decodeSearchKeyword(location.pathname.match(/(?:\/dashboard\/search\/(?:knowledge|files)\/(.*))/)?.[1] ?? '');
  // draft
  const draftModeColor = getDraftModeColor(theme);
  return (
    <AppBar
      position="fixed"
      className={classes.appBar}
      variant="outlined"
      elevation={0}
    >
      {/* Header and Footer Banners containing classification level of system */}
      <Toolbar
        style={{
          alignItems: 'center',
          marginTop: bannerHeightNumber + settingsMessagesBannerHeight,
          padding: 0,
          borderBottom: draftContext ? `1px solid ${draftModeColor}` : 'initial',
        }}
      >
        <div className={classes.logoContainer} style={navOpen ? { width: OPEN_BAR_WIDTH } : {}}>
          <Link to="/dashboard">
            <img
              src={isNotEmptyField(topBarLogo) ? topBarLogo : fallbackLogo}
              alt="logo"
              className={navOpen ? classes.logo : classes.logoCollapsed}
            />
          </Link>
        </div>
        {hasKnowledgeAccess && (
          <div
            style={{ display: 'flex', marginLeft: theme.spacing(3) }}
          >
            <SearchInput
              onSubmit={handleSearch}
              keyword={keyword}
              variant="topBar"
              placeholder={`${t_i18n('Search the platform')}...`}
              fullWidth={true}
              isNLQLoading={isNLQLoading}
            />
          </div>
        )}
        <div className={classes.barRight}>
          {!!draftContext && (
            <DraftContextBanner/>
          )}
          <div className={classes.barRightContainer}>
            {!draftContext && (
            <Security needs={[KNOWLEDGE]}>
              <>
                { ee.license_type === 'nfr' && <ItemBoolean variant="large" label={'EE DEV LICENSE'} status={false}/> }
                <Security needs={[KNOWLEDGE_KNASKIMPORT]}>
                  <UploadImport
                    variant="icon"
                    size="medium"
                    fontSize="medium"
                    color="inherit"
                  />
                </Security>
                <Tooltip title={t_i18n('Notifications')}>
                  <IconButton
                    size="medium"
                    aria-haspopup="true"
                    component={Link}
                    to="/dashboard/profile/notifications"
                    color={location.pathname === '/dashboard/profile/notifications' ? 'primary' : 'inherit'}
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
                <Tooltip title={t_i18n('Triggers')}>
                  <IconButton
                    size="medium"
                    aria-haspopup="true"
                    component={Link}
                    to="/dashboard/profile/triggers"
                    color={location.pathname === '/dashboard/profile/triggers' ? 'primary' : 'inherit'}
                  >
                    <AlarmOnOutlined fontSize="medium" />
                  </IconButton>
                </Tooltip>
              </>
            </Security>
            )}
            <IconButton
              color="inherit"
              size="medium"
              aria-owns={xtmOpen.open ? 'menu-appbar' : undefined}
              aria-haspopup="true"
              id="xtm-menu-button"
              onClick={handleOpenXtm}
            >
              <AppsOutlined fontSize="medium"/>
            </IconButton>
            <Popover
              anchorEl={xtmOpen.anchorEl}
              open={xtmOpen.open}
              onClose={handleCloseXtm}
              anchorOrigin={{
                vertical: 'bottom',
                horizontal: 'center',
              }}
              transformOrigin={{
                vertical: 'top',
                horizontal: 'center',
              }}
              disableScrollLock={true}
            >
              <Box sx={{ width: '300px', padding: '15px', textAlign: 'center' }}>
                <div className={classes.subtitle}>{t_i18n('Filigran eXtended Threat Management')}</div>
                <Grid container={true} spacing={3}>
                  <Grid item xs={12}>
                    <Tooltip title="XTM Hub">
                      <a className={classes.xtmItem} href={isNotEmptyField(xtmhubUrl) ? xtmhubUrl : 'https://xtmhub.filigran.io'} target="_blank" rel="noreferrer" onClick={handleCloseXtm}>
                        <Badge variant="dot" color="success">
                          <img style={{ width: '100%', paddingRight: 8, paddingLeft: 8 }} src={fileUri(theme.palette.mode === 'dark' ? xtmhubDark : xtmhubLight)} alt="XTM Hub" />
                        </Badge>
                      </a>
                    </Tooltip>
                  </Grid>
                  <Grid item xs={6}>
                    <Tooltip title={t_i18n('Current platform')}>
                      <a className={classes.xtmItemCurrent}>
                        <Badge variant="dot" color="success">
                          <img style={{ width: 40 }} src={fileUri(theme.palette.mode === 'dark' ? octiDark : octiLight)} alt="OCTI" />
                        </Badge>
                        <div className={classes.product}>OpenCTI</div>
                      </a>
                    </Tooltip>
                  </Grid>
                  <Grid item xs={6}>
                    <Tooltip title={isNotEmptyField(openBASUrl) ? t_i18n('Platform connected') : t_i18n('Get OpenBAS now')}>
                      <a className={classes.xtmItem} href={isNotEmptyField(openBASUrl) ? openBASUrl : 'https://filigran.io'} target="_blank" rel="noreferrer" onClick={handleCloseXtm}>
                        <Badge variant="dot" color={isNotEmptyField(openBASUrl) ? 'success' : 'warning'}>
                          <img style={{ width: 40 }} src={fileUri(theme.palette.mode === 'dark' ? obasDark : obasLight)} alt="OBAS" />
                        </Badge>
                        <div className={classes.product}>OpenBAS</div>
                      </a>
                    </Tooltip>
                  </Grid>
                </Grid>
              </Box>
            </Popover>
            <IconButton
              size="medium"
              aria-owns={menuOpen.open ? 'menu-appbar' : undefined}
              aria-haspopup="true"
              aria-label={t_i18n('Profile')}
              id="profile-menu-button"
              onClick={handleOpenMenu}
              color={
                location.pathname === '/dashboard/profile/me'
                  ? 'primary'
                  : 'inherit'
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
