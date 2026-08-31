import { OPEN_BAR_WIDTH, SMALL_BAR_WIDTH } from '@components/nav/navBarConstants';
import { AccountCircleOutlined, AlarmOnOutlined, NotificationsOutlined } from '@mui/icons-material';
import AppBar from '@mui/material/AppBar';
import { Header, HeaderGroup, IconButton, Menu, MenuContent, MenuItem, MenuTrigger, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useTheme } from '@mui/styles';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useCallback, useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { usePage } from 'use-analytics';
import { useFormatter } from '../../../components/i18n';
import ItemBoolean from '../../../components/ItemBoolean';
import SearchInput from '../../../components/SearchInput';
import type { Theme } from '../../../components/Theme';
import UploadImport from '../../../components/UploadImport';
import { APP_BASE_PATH, MESSAGING$, requestSubscription } from '../../../relay/environment';
import { isFilterGroupNotEmpty } from '../../../utils/filters/filtersUtils';
import useAuth from '../../../utils/hooks/useAuth';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useGranted, { KNOWLEDGE, KNOWLEDGE_KNASKIMPORT } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { decodeSearchKeyword, handleSearchByFilter, handleSearchByKeyword } from '../../../utils/SearchUtils';
import Security from '../../../utils/Security';
import FeedbackCreation from '../cases/feedbacks/FeedbackCreation';
import AskArianeButton from '../chatbox/AskArianeButton';
import CtemCommandCenterButton from '../chatbox/CtemCommandCenterButton';
import { CGUStatus } from '../settings/Experience';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import useTopBanner from '../../../utils/hooks/useTopBanner';
import { TopBarNotificationNumberSubscription$data } from './__generated__/TopBarNotificationNumberSubscription.graphql';
import { TopBarNewsFeedNumberSubscription$data } from './__generated__/TopBarNewsFeedNumberSubscription.graphql';
import { TopBarQuery } from './__generated__/TopBarQuery.graphql';
import { THEME_DARK_DEFAULT_BACKGROUND } from '../../../components/ThemeDark';
import { useAINLQ } from '../common/ai/AINLQ';
import TopBarIconLink from './TopBarIconLink';
import { TOP_BAR_SEARCH_MAX_WIDTH, TOP_BAR_SEARCH_MIN_WIDTH } from './topBarConstants';

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

const topBarNewsFeedNumberSubscription = graphql`
  subscription TopBarNewsFeedNumberSubscription {
    newsFeedsNumber {
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
    myUnreadNewsFeedsCount
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
    isXTMHubAccessible,
    me,
  } = useAuth();
  const isAllNewsFeedUnsubscribed = me.unsubscribed_news_feed_types?.includes('*') ?? false;
  const draftContext = useDraftContext();
  const hasKnowledgeAccess = useGranted([KNOWLEDGE]);
  const showAiCluster = hasKnowledgeAccess
    && filigran_chatbot_ai_cgu_status !== CGUStatus.disabled;
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const { height: topBannerHeight } = useTopBanner();
  const [notificationsNumber, setNotificationsNumber] = useState<null | number>(
    null,
  );
  const [newsFeedsNumberFromSub, setNewsFeedsNumberFromSub] = useState<null | number>(null);

  const data = usePreloadedQuery(topBarQuery, queryRef);
  const page = usePage();
  const handleNewNotificationsNumber = useCallback((
    response: TopBarNotificationNumberSubscription$data | null | undefined | unknown,
  ) => {
    const notificationNumber = response ? (response as TopBarNotificationNumberSubscription$data).notificationsNumber?.count : null;
    return setNotificationsNumber(notificationNumber ?? null);
  }, [setNotificationsNumber]);
  const handleNewNewsFeedNumber = useCallback((
    response: TopBarNewsFeedNumberSubscription$data | null | undefined | unknown,
  ) => {
    const newsFeedNumber = response ? (response as TopBarNewsFeedNumberSubscription$data).newsFeedsNumber?.count : null;
    return setNewsFeedsNumberFromSub(newsFeedNumber ?? null);
  }, [setNewsFeedsNumberFromSub]);
  const isNewNotification = notificationsNumber !== null
    ? notificationsNumber > 0
    : (data.myUnreadNotificationsCount ?? 0) > 0;
  const newsFeedCount = isXTMHubAccessible && !isAllNewsFeedUnsubscribed
    ? (newsFeedsNumberFromSub !== null ? newsFeedsNumberFromSub : (data.myUnreadNewsFeedsCount ?? 0))
    : 0;
  const isNewNewsFeed = newsFeedCount > 0;
  const hasUnread = isNewNotification || isNewNewsFeed;
  // The bar shows a dot, never a count; the total is still announced.
  const unreadCount = (notificationsNumber !== null ? notificationsNumber : (data.myUnreadNotificationsCount ?? 0)) + newsFeedCount;
  const subConfig = useMemo(
    () => ({
      subscription: topBarNotificationNumberSubscription,
      variables: {},
      onNext: handleNewNotificationsNumber,
    }),
    [topBarNotificationNumberSubscription, handleNewNotificationsNumber],
  );
  useSubscription(subConfig);

  const shouldSubscribeToNewsFeed = isXTMHubAccessible && !isAllNewsFeedUnsubscribed;
  useEffect(() => {
    if (!shouldSubscribeToNewsFeed) return undefined;
    const sub = requestSubscription({
      subscription: topBarNewsFeedNumberSubscription,
      variables: {},
      onNext: handleNewNewsFeedNumber,
    });
    return () => sub.dispose();
  }, [shouldSubscribeToNewsFeed, handleNewNewsFeedNumber]);
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
  // The library's Menu owns its own anchoring, so the product only tracks openness.
  const [menuOpen, setMenuOpen] = useState(false);
  const [openDrawer, setOpenDrawer] = useState(false);

  const { search: nlqSearch, isLoading: isNLQLoading } = useAINLQ({
    onFiltersResolved: (keyword, filters, notResolvedValues) => {
      let hasNonEmptyFilters = false;
      if (filters) {
        try {
          hasNonEmptyFilters = isFilterGroupNotEmpty(JSON.parse(filters));
        } catch {
          hasNonEmptyFilters = false;
        }
      }
      if (notResolvedValues && notResolvedValues.length > 0) {
        MESSAGING$.notifyNLQ(`${t_i18n('Some entities you mentioned have not been found in the platform')}: ${notResolvedValues}`);
      } else if (!hasNonEmptyFilters) {
        MESSAGING$.notifyNLQ(t_i18n('The NLQ model didn\'t find filters corresponding to your question'));
      }
      handleSearchByFilter(keyword, 'nlq', navigate, filters);
    },
    onError: (msg) => MESSAGING$.notifyError(msg),
  });

  const handleCloseMenu = () => {
    setMenuOpen(false);
  };

  const handleSearch = (searchKeyword: string, askAI = false, agentSlug?: string) => {
    if (askAI && isEnterpriseEdition) {
      nlqSearch(searchKeyword, agentSlug);
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

  // Stops stay OPAQUE: the library's Header carries the glass itself, a ::before layer at
  // Figma's 94% over a 4px backdrop blur.
  const getAppTopBarGradient = (): { start: string; end: string } => {
    if (theme.palette.background.gradient?.start && theme.palette.background.gradient?.end) {
      return {
        start: theme.palette.background.gradient.start,
        end: theme.palette.background.gradient.end,
      };
    }
    return {
      start: THEME_DARK_DEFAULT_BACKGROUND,
      end: theme.palette.designSystem.background.bg1,
    };
  };

  const appBarGradient = getAppTopBarGradient();

  return (
    // Radix tooltips need a provider in scope; scoped to this bar, not the whole app.
    <>
      <Header
        // FDS-WORKAROUND #14: bar positioned product-side, `fullWidth={false}` with it — see fds-migration/LIBRARY-FEEDBACK.md #14
        fullWidth={false}
        style={{
          position: 'fixed',
          // The three banner offsets stack, exactly as the Toolbar's marginTop did.
          top: bannerHeightNumber + settingsMessagesBannerHeight + topBannerHeight,
          left: navOpen ? OPEN_BAR_WIDTH : SMALL_BAR_WIDTH,
          right: 0,
          zIndex: theme.zIndex.appBar,
          // FDS-WORKAROUND #15: re-declare the assembled gradient on the element — see fds-migration/LIBRARY-FEEDBACK.md #15
          '--gradient-default': `linear-gradient(90deg, ${appBarGradient.start} 0%, ${appBarGradient.end} 100%)`,
        } as React.CSSProperties}
      >
        <HeaderGroup
          // `grow` caps below this bar's ceiling — see fds-migration/LIBRARY-FEEDBACK.md #17.
          // NOT `HeaderSearch` (LIBRARY-FEEDBACK.md #54) — see fds-migration/MIGRATION-DECISIONS.md#topbar-search-not-headersearch
          grow="unbounded"
          style={{
            minWidth: TOP_BAR_SEARCH_MIN_WIDTH,
            maxWidth: TOP_BAR_SEARCH_MAX_WIDTH,
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
        </HeaderGroup>
        <HeaderGroup>
          <Security needs={[KNOWLEDGE]}>
            <>
              {
                filigran_chatbot_ai_cgu_status !== CGUStatus.disabled && (
                  <>
                    <AskArianeButton />
                    <CtemCommandCenterButton />
                  </>
                )
              }
            </>
          </Security>
          {/* The rule belongs to the cluster that follows it, and only draws
              when an AI cluster precedes it. */}
          <HeaderGroup separatorBefore={showAiCluster}>
            {!draftContext && (
              <Security needs={[KNOWLEDGE]}>
                <>
                  {ee.license_type === 'nfr' && <ItemBoolean label="EE DEV LICENSE" status={false} />}
                  <Security needs={[KNOWLEDGE_KNASKIMPORT]} capabilitiesInDraft={[KNOWLEDGE_KNASKIMPORT]}>
                    <UploadImport
                      variant="icon"
                      fontSize="medium"
                      size="default"
                    />
                  </Security>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <TopBarIconLink
                        aria-label={t_i18n('Triggers')}
                        to="/dashboard/profile/triggers"
                        active={location.pathname === '/dashboard/profile/triggers'}
                        icon={<AlarmOnOutlined fontSize="medium" />}
                      />
                    </TooltipTrigger>
                    <TooltipContent>{t_i18n('Triggers')}</TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <TopBarIconLink
                        aria-label={t_i18n('Notifications')}
                        to="/dashboard/profile/notifications/alerts"
                        active={location.pathname.startsWith('/dashboard/profile/notifications')}
                        icon={<NotificationsOutlined fontSize="medium" />}
                        // Marks the control, never the glyph: the glyph sits in an aria-hidden
                        // span, where the badge's description reaches nobody.
                        badge={{
                          content: unreadCount,
                          dot: true,
                          invisible: !hasUnread,
                          accessibleText: `${unreadCount} ${t_i18n('unread')}`,
                        }}
                      />
                    </TooltipTrigger>
                    <TooltipContent>{t_i18n('Notifications')}</TooltipContent>
                  </Tooltip>
                </>
              </Security>
            )}
            <Menu open={menuOpen} onOpenChange={setMenuOpen}>
              {/* MenuTrigger + asChild around an IconButton is the library's canonical pairing. */}
              <MenuTrigger asChild>
                <IconButton
                  priority="tertiary"
                  aria-label={t_i18n('Profile')}
                  id="profile-menu-button"
                  active={location.pathname === '/dashboard/profile/me'}
                  icon={<AccountCircleOutlined fontSize="medium" />}
                />
              </MenuTrigger>
              <MenuContent align="end">
                <MenuItem asChild onSelect={handleCloseMenu}>
                  <Link to="/dashboard/profile">{t_i18n('Profile')}</Link>
                </MenuItem>
                <MenuItem onSelect={handleOpenDrawer}>{t_i18n('Feedback')}</MenuItem>
                <MenuItem asChild onSelect={handleCloseMenu}>
                  <a href={`${APP_BASE_PATH}/logout`} rel="noreferrer">{t_i18n('Logout')}</a>
                </MenuItem>
              </MenuContent>
            </Menu>
          </HeaderGroup>
        </HeaderGroup>
      </Header>
      <FeedbackCreation
        openDrawer={openDrawer}
        handleCloseDrawer={handleCloseDrawer}
      />
    </>
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
