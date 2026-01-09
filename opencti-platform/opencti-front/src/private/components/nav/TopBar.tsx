import IconButton from '@common/button/IconButton';
import { getDraftModeColor } from '@components/common/draft/DraftChip';
import DraftContextBanner from '@components/drafts/DraftContextBanner';
import { TopBarAskAINLQMutation, TopBarAskAINLQMutation$data } from '@components/nav/__generated__/TopBarAskAINLQMutation.graphql';
import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/LeftBar';
import { AccountCircleOutlined, AlarmOnOutlined, NotificationsOutlined } from '@mui/icons-material';
import { alpha, Badge, Stack } from '@mui/material';
import AppBar from '@mui/material/AppBar';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Toolbar from '@mui/material/Toolbar';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { usePage } from 'use-analytics';
import { useFormatter } from '../../../components/i18n';
import ItemBoolean from '../../../components/ItemBoolean';
import SearchInput from '../../../components/SearchInput';
import type { Theme } from '../../../components/Theme';
import UploadImport from '../../../components/UploadImport';
import { APP_BASE_PATH, MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';
import { isFilterGroupNotEmpty } from '../../../utils/filters/filtersUtils';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useAuth from '../../../utils/hooks/useAuth';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useGranted, { KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { decodeSearchKeyword, handleSearchByFilter, handleSearchByKeyword } from '../../../utils/SearchUtils';
import Security from '../../../utils/Security';
import FeedbackCreation from '../cases/feedbacks/FeedbackCreation';
import AskArianeButton from '../chatbox/AskArianeButton';
import { CGUStatus } from '../settings/Experience';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import { TopBarNotificationNumberSubscription$data } from './__generated__/TopBarNotificationNumberSubscription.graphql';
import { TopBarQuery } from './__generated__/TopBarQuery.graphql';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  appBar: {
    zIndex: theme.zIndex.drawer - 1,
    background: 0,
    backgroundColor: theme.palette.background.nav,
    paddingTop: theme.spacing(0.2),
    borderLeft: 0,
    borderRight: 0,
    borderTop: 0,
    color: theme.palette.text?.primary,
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
  const { t_i18n } = useFormatter();
  const {
    bannerSettings: { bannerHeightNumber },
    settings: {
      platform_enterprise_edition: ee,
      filigran_chatbot_ai_cgu_status,
    },
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

  const appBarGradient = theme.palette.background.gradient?.start && theme.palette.background.gradient?.end
    ? `${alpha(theme.palette.background.gradient.start, 0.9)} 0%, ${alpha(theme.palette.background.gradient.end, 0.9)}`
    : 'rgba(7, 13, 25, 0.90) 0%, rgba(12, 21, 36, 0.90)}';

  return (
    <AppBar
      position="fixed"
      elevation={0}
      sx={{
        marginLeft: navOpen ? `${OPEN_BAR_WIDTH}px` : `${SMALL_BAR_WIDTH}px`,
        width: navOpen ? `calc(100% - ${OPEN_BAR_WIDTH}px)` : `calc(100% - ${SMALL_BAR_WIDTH}px)`,
        height: 68,
        backgroundColor: 'transparent',
        backdropFilter: 'blur(4px)',
      }}
    >
      {/* Header and Footer Banners containing classification level of system */}
      <Toolbar
        style={{
          alignItems: 'center',
          marginTop: bannerHeightNumber + settingsMessagesBannerHeight,
          height: '100%',
          minHeight: 68,
          paddingLeft: theme.spacing(3),
          paddingRight: theme.spacing(3),
          display: 'flex',
          justifyContent: 'space-between',
          background: `linear-gradient(90deg, ${appBarGradient} 100%)`,
          borderBottom: draftContext ? `1px solid ${draftModeColor}` : `1px solid ${theme.palette.background.secondary}`,
        }}
      >
        {hasKnowledgeAccess && (
          <SearchInput
            onSubmit={handleSearch}
            keyword={keyword}
            variant="topBar"
            placeholder={`${t_i18n('Search the platform')}...`}
            isNLQLoading={isNLQLoading}
          />
        )}
        <div>
          <Stack direction="row" gap={1} alignItems="center">
            {draftContext && (
              <DraftContextBanner />
            )}

            {!draftContext && (
              <Security needs={[KNOWLEDGE]}>
                <>
                  {
                    filigran_chatbot_ai_cgu_status !== CGUStatus.disabled && (
                      <AskArianeButton />
                    )
                  }

                  { ee.license_type === 'nfr' && <ItemBoolean variant="large" label="EE DEV LICENSE" status={false} /> }
                  <Security needs={[KNOWLEDGE_KNASKIMPORT]}>
                    <UploadImport
                      variant="icon"
                      fontSize="medium"
                      size="default"
                    />
                  </Security>
                  <Tooltip title={t_i18n('Triggers')}>
                    <IconButton
                      aria-haspopup="true"
                      size="default"
                      component={Link}
                      to="/dashboard/profile/triggers"
                      selected={location.pathname === '/dashboard/profile/triggers'}
                    >
                      <AlarmOnOutlined fontSize="medium" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title={t_i18n('Notifications')}>
                    <IconButton
                      aria-haspopup="true"
                      size="default"
                      component={Link}
                      to="/dashboard/profile/notifications"
                      selected={location.pathname === '/dashboard/profile/notifications'}
                    >
                      <Badge
                        color="secondary"
                        variant="dot"
                        invisible={!isNewNotification}
                      >
                        <NotificationsOutlined fontSize="medium" />
                      </Badge>
                    </IconButton>
                  </Tooltip>
                </>
              </Security>
            )}
            <IconButton
              aria-owns={menuOpen.open ? 'menu-appbar' : undefined}
              size="default"
              aria-haspopup="true"
              aria-label={t_i18n('Profile')}
              id="profile-menu-button"
              onClick={handleOpenMenu}
              selected={location.pathname === '/dashboard/profile/me'}
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
          </Stack>
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
          fallback={(
            <AppBar
              position="fixed"
              className={classes.appBar}
              variant="elevation"
              elevation={1}
            />
          )}
        >
          <TopBarComponent queryRef={queryRef} />
        </React.Suspense>
      )}
    </>
  );
};

export default TopBar;
