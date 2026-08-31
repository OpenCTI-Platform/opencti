import { Navbar, NavbarItem, NavbarSeparator, NavbarSubmenu, NavbarSubmenuItem, ProductSwitcher } from '@filigran/design-system';
import { useTheme } from '@mui/styles';
import React, { useState } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';
import { THEME_DARK_DEFAULT_BACKGROUND } from '../../../components/ThemeDark';
import logoOpenAEVDark from '../../../static/images/logo_open_aev_dark.svg';
import logoOpenAEVLight from '../../../static/images/logo_open_aev_light.svg';
import logoXTMHubDark from '../../../static/images/logo_xtm_hub_dark.svg';
import logoXTMHubLight from '../../../static/images/logo_xtm_hub_light.svg';
import LogoCollapsedOrange from '../../../static/images/logo_orange.svg';
import LogoTextOrange from '../../../static/images/logo_text_orange.svg';
import useAuth from '../../../utils/hooks/useAuth';
import useTopBanner from '../../../utils/hooks/useTopBanner';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { isNotEmptyField } from '../../../utils/utils';
import { NavBarQuery } from './__generated__/NavBarQuery.graphql';
import MadeByFiligran from './MadeByFiligran';
import { readNavOpen, readSelectedMenu, writeNavOpen, writeSelectedMenu } from './navBarConstants';
import useNavMenu, { NavGroup, NavItem, NavSubItem } from './useNavMenu';

const OPENAEV_FALLBACK_URL = 'https://filigran.io/solutions/open-aev/';
const XTMHUB_FALLBACK_URL = 'https://hub.filigran.io';

export const navBarQuery = graphql`
  query NavBarQuery {
    settings {
      platform_whitemark
    }
  }
`;

/**
 * Route matching, reproduced verbatim from the rail this component replaces.
 * The `/dashboard/data` special case exists because drafts share the prefix.
 */
export const isRouteSelected = (pathname: string, link: string, exact?: boolean): boolean => {
  if (exact) return pathname === link;
  if (link === '/dashboard/data' && pathname.includes('/import/draft/')) return false;
  return pathname === link || pathname.startsWith(`${link}/`);
};

/**
 * Props of the pure rail view.
 */
export interface NavBarViewProps {
  groups: NavGroup[];
  pathname: string;
  collapsed: boolean;
  onCollapsedChange: (collapsed: boolean) => void;
  openSubmenus: string[];
  onSubmenuOpenChange: (id: string, open: boolean) => void;
  submenuShowIcons: boolean;
  /** Inline background, set only when a custom theme must be honoured. */
  customBackground?: string;
  /** Inline accent, overriding the library's fixed brand token. */
  accentColor?: string;
  /** Space the banners take at the top of the viewport, as a CSS length. */
  topOffset: string;
  /** Space the banners take at the bottom of the viewport, as a CSS length. */
  bottomOffset: string;
  header: React.ReactNode;
  footer: React.ReactNode;
  navLabel: string;
}

export const NavBarView: React.FC<NavBarViewProps> = ({
  groups,
  pathname,
  collapsed,
  onCollapsedChange,
  openSubmenus,
  onSubmenuOpenChange,
  submenuShowIcons,
  customBackground,
  accentColor,
  topOffset,
  bottomOffset,
  header,
  footer,
  navLabel,
}) => {
  // FDS-WORKAROUND #11: sticky, definite-height rail geometry — remove when the <nav> takes the height it is given — see fds-migration/LIBRARY-FEEDBACK.md #11
  const navStyle: React.CSSProperties & Record<string, string | undefined> = {
    position: 'sticky',
    top: topOffset,
    alignSelf: 'flex-start',
    height: `calc(100dvh - ${topOffset} - ${bottomOffset})`,
  };
  if (customBackground) navStyle.background = customBackground;
  if (accentColor) {
    navStyle['--color-filigran-brand-primary'] = accentColor;
    // FDS-WORKAROUND #6: re-derive the brand tint tokens — remove when derived tokens follow a subtree override — see fds-migration/LIBRARY-FEEDBACK.md #6
    navStyle['--color-filigran-brand-primary-transparency-10'] = `color-mix(in srgb, ${accentColor} 10%, transparent)`;
    navStyle['--color-filigran-brand-primary-transparency-55'] = `color-mix(in srgb, ${accentColor} 55%, transparent)`;
  }

  // FDS-WORKAROUND #2: submenu icons composed product-side — remove when a slotted child keeps icon handling — see fds-migration/LIBRARY-FEEDBACK.md #2
  const renderSubItem = (sub: NavSubItem) => (
    <NavbarSubmenuItem key={sub.link} asChild>
      <Link
        to={sub.link}
        aria-current={isRouteSelected(pathname, sub.link, sub.exact) ? 'page' : undefined}
      >
        {submenuShowIcons && sub.icon}
        <span>{sub.label}</span>
      </Link>
    </NavbarSubmenuItem>
  );

  // FDS-WORKAROUND #7: row body re-implemented for asChild — remove when asChild composes the row body — see fds-migration/LIBRARY-FEEDBACK.md #7
  const renderRowBody = (icon: React.ReactNode, label: string) => (
    <>
      <span className="inline-flex shrink-0" aria-hidden="true">{icon}</span>
      <span className={collapsed ? 'sr-only' : 'flex-1 truncate text-left'}>{label}</span>
    </>
  );

  const renderItem = (item: NavItem) => {
    if (!item.subItems || item.subItems.length === 0) {
      return (
        <NavbarItem key={item.id} asChild tooltipLabel={item.label}>
          <Link
            to={item.link}
            aria-current={isRouteSelected(pathname, item.link, item.exact) ? 'page' : undefined}
          >
            {renderRowBody(item.icon, item.label)}
          </Link>
        </NavbarItem>
      );
    }
    return (
      <NavbarSubmenu
        key={item.id}
        label={item.label}
        icon={item.icon}
        // FDS-WORKAROUND #10: accordion state bound only when expanded — remove when the flyout gets its own prop — see fds-migration/LIBRARY-FEEDBACK.md #10
        open={collapsed ? undefined : openSubmenus.includes(item.id)}
        onOpenChange={collapsed ? undefined : (open) => onSubmenuOpenChange(item.id, open)}
        // `to` makes the parent row navigable ONLY while the rail is collapsed, which is
        // exactly what the previous `handleParentClick` did: expanded, a click toggled the
        // accordion; collapsed, it navigated to the parent route.
        to={item.link}
      >
        {item.subItems.map(renderSubItem)}
      </NavbarSubmenu>
    );
  };

  return (
    <Navbar
      className="app-navbar"
      aria-label={navLabel}
      collapsed={collapsed}
      onCollapsedChange={onCollapsedChange}
      submenuShowIcons={submenuShowIcons}
      style={navStyle}
      header={header}
      footer={footer}
    >
      {groups.map((group, index) => (
        <React.Fragment key={group.id}>
          {index > 0 && <NavbarSeparator />}
          {group.items.map(renderItem)}
        </React.Fragment>
      ))}
    </Navbar>
  );
};

interface NavBarComponentProps {
  queryRef: NonNullable<ReturnType<typeof useQueryLoading<NavBarQuery>>>;
}

const NavBarComponent: React.FC<NavBarComponentProps> = ({ queryRef }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const {
    me: { submenu_auto_collapse: submenuAutoCollapse, submenu_show_icons: submenuShowIcons, draftContext },
    settings: {
      platform_openaev_url: openAEVUrl,
      platform_xtmhub_url: xtmhubUrl,
      xtm_hub_registration_status: xtmhubStatus,
    },
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const { height: topBannerHeight } = useTopBanner();
  // Mirrors the app shell's own offsets (private/Index.tsx): the classification banners take
  // the banner height at the top and at the bottom, the notification banner `topBannerHeight`
  // at the top only.
  const topOffset = `${topBannerHeight + bannerHeightNumber}px`;
  const bottomOffset = `${bannerHeightNumber}px`;
  const hasXtmHubAccess = useGranted([SETTINGS_SETMANAGEXTMHUB]);
  const data = usePreloadedQuery<NavBarQuery>(navBarQuery, queryRef);
  const groups = useNavMenu();

  const [navOpen, setNavOpen] = useState(readNavOpen());
  const [openSubmenus, setOpenSubmenus] = useState<string[]>(readSelectedMenu());

  const handleCollapsedChange = (collapsed: boolean) => {
    // Closing every submenu on toggle is the legacy behaviour: the collapsed
    // rail shows submenus as flyouts, so a persisted expanded accordion would
    // reopen unexpectedly the next time the rail expands.
    setOpenSubmenus([]);
    writeSelectedMenu([]);
    setNavOpen(!collapsed);
    writeNavOpen(!collapsed);
  };

  const handleSubmenuOpenChange = (id: string, open: boolean) => {
    // `submenu_auto_collapse` is a user preference: when on, opening one
    // submenu closes the others; when off, several stay open at once.
    let updated: string[];
    if (!open) {
      updated = openSubmenus.filter((menu) => menu !== id);
    } else if (submenuAutoCollapse) {
      updated = [id];
    } else {
      updated = [...openSubmenus.filter((menu) => menu !== id), id];
    }
    setOpenSubmenus(updated);
    writeSelectedMenu(updated);
  };

  const isLightTheme = theme.palette.mode === 'light';

  /**
   * The rail background, reproduced from the component this replaces.
   */
  const customBackground = (() => {
    // The light rail never honoured `theme_background`: it hardcoded two
    // constants. Nothing to preserve, so the library paints it.
    if (isLightTheme) return undefined;
    const start = theme.palette.background?.gradient?.start ?? theme.palette.background?.default;
    const end = theme.palette.background?.gradient?.end ?? theme.palette.background?.secondary;
    // `gradient.start` is `theme_background || THEME_DARK_DEFAULT_BACKGROUND`,
    // so equality with the default is an exact test for "no custom background".
    if (start === THEME_DARK_DEFAULT_BACKGROUND) return undefined;
    return `linear-gradient(100deg, ${start} 0%, ${end} 100%)`;
  })();

  // FDS-WORKAROUND #1: selected-row accent resolved product-side — remove when Navbar exposes an accent prop — see fds-migration/LIBRARY-FEEDBACK.md #1
  const accentColor = draftContext
    ? theme.palette.designSystem?.alert?.warning?.primary
    : theme.palette.primary?.main;

  const productLogo = draftContext ? LogoTextOrange : theme.logo;
  const productLogoCollapsed = draftContext ? LogoCollapsedOrange : theme.logo_collapsed;
  const xtmHubRegistered = xtmhubStatus === 'registered' || !hasXtmHubAccess;

  return (
    <NavBarView
      groups={groups}
      pathname={location.pathname}
      collapsed={!navOpen}
      onCollapsedChange={handleCollapsedChange}
      openSubmenus={openSubmenus}
      onSubmenuOpenChange={handleSubmenuOpenChange}
      submenuShowIcons={submenuShowIcons ?? false}
      customBackground={customBackground}
      accentColor={accentColor}
      topOffset={topOffset}
      bottomOffset={bottomOffset}
      navLabel={t_i18n('Main navigation')}
      header={(
        <ProductSwitcher
          label={t_i18n('Switch product')}
          logo={<img src={productLogo} alt="" width={126} height={28} style={{ objectFit: 'contain', objectPosition: 'left' }} />}
          logoCollapsed={<img src={productLogoCollapsed} alt="" height={28} width={28} style={{ objectFit: 'contain' }} />}
          logoTo="/dashboard"
          // The logo link and the "Home" row both point at /dashboard, so the logo cannot be
          // named "Home": two links with the same accessible name inside one navigation are
          // ambiguous for screen readers and break the e2e page object's `exact` name lookup.
          // "logo" is the accessible name the replaced rail exposed (its <img alt="logo">), and
          // two settings specs anchor on it, so keep it identical.
          logoLabel="logo"
          options={[
            {
              id: 'openaev',
              label: t_i18n('OpenAEV'),
              tooltip: isNotEmptyField(openAEVUrl) ? t_i18n('Platform connected') : t_i18n('Get OpenAEV now'),
              // Option logos fill their own slot; a fixed width overflows it.
              logo: <img src={isLightTheme ? logoOpenAEVLight : logoOpenAEVDark} alt="" style={{ width: '100%', height: 'auto', objectFit: 'contain' }} />,
              href: isNotEmptyField(openAEVUrl) ? (openAEVUrl as string) : OPENAEV_FALLBACK_URL,
            },
            {
              id: 'xtmhub',
              label: t_i18n('XTM Hub'),
              logo: <img src={isLightTheme ? logoXTMHubLight : logoXTMHubDark} alt="" style={{ width: '100%', height: 'auto', objectFit: 'contain' }} />,
              ...(xtmHubRegistered
                ? { href: isNotEmptyField(xtmhubUrl) ? (xtmhubUrl as string) : XTMHUB_FALLBACK_URL }
                : { to: '/dashboard/settings/experience' }),
            },
          ]}
        />
      )}
      footer={!data?.settings?.platform_whitemark && (
        <MadeByFiligran collapsed={!navOpen} />
      )}
    />
  );
};

const NavBar = () => {
  const queryRef = useQueryLoading<NavBarQuery>(navBarQuery, {});
  return queryRef ? (
    <React.Suspense>
      <NavBarComponent queryRef={queryRef} />
    </React.Suspense>
  ) : null;
};

export default NavBar;
