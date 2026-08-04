import { Navbar, NavbarItem, NavbarSeparator, NavbarSubmenu, NavbarSubmenuItem, ProductSwitcher } from '@filigran/design-system';
import { useTheme } from '@mui/styles';
import React, { useState } from 'react';
import { graphql, usePreloadedQuery } from 'react-relay';
import { Link, useLocation } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import { Theme } from '../../../components/Theme';
import { THEME_DARK_DEFAULT_BACKGROUND } from '../../../components/ThemeDark';
import logoFiligran from '../../../static/images/logo_filigran_full.svg';
import logoOpenAEVDark from '../../../static/images/logo_open_aev_dark.svg';
import logoOpenAEVLight from '../../../static/images/logo_open_aev_light.svg';
import logoXTMHubDark from '../../../static/images/logo_xtm_hub_dark.svg';
import logoXTMHubLight from '../../../static/images/logo_xtm_hub_light.svg';
import LogoCollapsedOrange from '../../../static/images/logo_orange.svg';
import LogoTextOrange from '../../../static/images/logo_text_orange.svg';
import useAuth from '../../../utils/hooks/useAuth';
import useGranted, { SETTINGS_SETMANAGEXTMHUB } from '../../../utils/hooks/useGranted';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { isNotEmptyField } from '../../../utils/utils';
import { NavBarQuery } from './__generated__/NavBarQuery.graphql';
import { readNavOpen, readSelectedMenu, writeNavOpen, writeSelectedMenu } from './navBarConstants';
import useNavMenu, { NavGroup, NavItem, NavSubItem } from './useNavMenu';

const OPENAEV_FALLBACK_URL = 'https://filigran.io/solutions/open-aev/';
const XTMHUB_FALLBACK_URL = 'https://hub.filigran.io';

export const navBarQuery = graphql`
  query NavBarQuery {
    settings {
      platform_whitemark
      platform_title
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
 * Props of the pure rail view. Everything is already resolved by the data
 * component below, so this view renders without Relay, without the user
 * context and without entity settings — which is what makes the rendering
 * contract (real anchors, `aria-current`, collapsed-only parent navigation,
 * the accent override) unit-testable at all.
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
  header,
  footer,
  navLabel,
}) => {
  const navStyle: React.CSSProperties & Record<string, string | undefined> = {};
  if (customBackground) navStyle.background = customBackground;
  if (accentColor) {
    navStyle['--color-filigran-brand-primary'] = accentColor;
    // The library derives the selected-row tint from a SECOND token, and
    // declares it on `:root` as a `color-mix` of the first. Custom properties
    // are substituted where they are declared, not where they are used, so
    // that derived token is frozen against the root brand colour and an
    // override placed here would never reach it: the left border followed the
    // custom accent while the row tint stayed Filigran blue. Re-deriving it
    // with the library's own formula is what makes the override complete.
    navStyle['--color-filigran-brand-primary-transparency'] = `color-mix(in srgb, ${accentColor} 10%, transparent)`;
    navStyle['--color-filigran-brand-primary-transparency-50'] = `color-mix(in srgb, ${accentColor} 50%, transparent)`;
  }

  /**
   * Submenu rows are real anchors so Ctrl/Cmd-click and "open in new tab"
   * work, which means `asChild`. `asChild` slots our own element in and makes
   * the library's `icon`/`showIcon` props no-ops, so the `submenu_show_icons`
   * user preference has to be honoured here instead of by the ambient
   * `Navbar submenuShowIcons`. That prop is still passed to `Navbar` so the
   * context stays correct, and so this composition can be deleted unchanged
   * the day the library can inject an icon into a slotted child.
   */
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

  /**
   * `asChild` slots our anchor in place of the library's own <button>, so the
   * row's internal layout is ours to reproduce: the library hides the label
   * with `sr-only` while the rail is collapsed and shows the tooltip instead.
   * Reproduced verbatim here — dropping the label instead of hiding it would
   * strip the accessible name the collapsed rail is navigated by.
   * See fds-migration/LIBRARY-FEEDBACK.md, "asChild rows must re-implement the
   * row body, including the collapsed label".
   */
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
        open={openSubmenus.includes(item.id)}
        onOpenChange={(open) => onSubmenuOpenChange(item.id, open)}
        // `to` makes the parent row navigable ONLY while the rail is
        // collapsed, which is exactly what the previous `handleParentClick`
        // did: expanded, a click toggled the accordion; collapsed, it
        // navigated to the parent route.
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
  } = useAuth();
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
   *
   * Applied ONLY when a custom theme is in use. OpenCTI's built-in dark theme
   * already derives its gradient from the very design-system tokens the
   * library paints with, so on a standard install we let the library paint
   * itself and the product gets the real design-system rendering — the point
   * of this migration. An administrator who configured `theme_background`,
   * however, expects the rail to follow it, and losing that would be a
   * functional regression rather than a visual change; the legacy gradient is
   * then restored inline, which wins over the library's class.
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

  /**
   * Selected-row accent.
   *
   * COMPENSATION — see LIBRARY-FEEDBACK entries 1 and 6. `NavbarItem` paints
   * its `aria-current="page"` state from the fixed brand token
   * `--color-filigran-brand-primary`, and fills the row from a token derived
   * from it. OpenCTI lets an administrator set `theme_primary`, and swaps the
   * accent to the warning colour inside a draft. The colour is resolved here
   * and the tokens are overridden on the `<nav>` (see `navStyle` in the view,
   * which has to re-derive the tint token as well).
   * REMOVAL TEST: at a pin where `Navbar` exposes an accent prop, delete this
   * block, pass the same colour to that prop, and confirm `NavBar.test.tsx`
   * still passes — it asserts the resolved accent, not the mechanism.
   */
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
      navLabel={t_i18n('Main navigation')}
      header={(
        <ProductSwitcher
          label={t_i18n('Switch product')}
          logo={<img src={productLogo} alt="" width={126} height={28} style={{ objectFit: 'contain', objectPosition: 'left' }} />}
          logoCollapsed={<img src={productLogoCollapsed} alt="" height={28} width={28} style={{ objectFit: 'contain' }} />}
          logoTo="/dashboard"
          // The logo link and the "Home" row both point at /dashboard, so the
          // logo cannot be named "Home": two links with the same accessible
          // name inside one navigation are ambiguous for screen readers and
          // break the e2e page object's `exact` name lookup. The platform
          // title is what the logo actually depicts.
          logoLabel={data?.settings?.platform_title || 'OpenCTI'}
          options={[
            {
              id: 'openaev',
              label: t_i18n('OpenAEV'),
              tooltip: isNotEmptyField(openAEVUrl) ? t_i18n('Platform connected') : t_i18n('Get OpenAEV now'),
              logo: <img src={isLightTheme ? logoOpenAEVLight : logoOpenAEVDark} alt="" width={126} />,
              href: isNotEmptyField(openAEVUrl) ? (openAEVUrl as string) : OPENAEV_FALLBACK_URL,
            },
            {
              id: 'xtmhub',
              label: t_i18n('XTM Hub'),
              logo: <img src={isLightTheme ? logoXTMHubLight : logoXTMHubDark} alt="" width={126} />,
              ...(xtmHubRegistered
                ? { href: isNotEmptyField(xtmhubUrl) ? (xtmhubUrl as string) : XTMHUB_FALLBACK_URL }
                : { to: '/dashboard/settings/experience' }),
            },
          ]}
        />
      )}
      footer={!data?.settings?.platform_whitemark && (
        <div className="app-navbar-made-by">
          {navOpen && <span>{t_i18n('Made by')}</span>}
          <img alt="" src={logoFiligran} width={navOpen ? 48 : 12} height="12" />
        </div>
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
