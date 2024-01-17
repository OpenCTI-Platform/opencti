import React, { FunctionComponent } from 'react';
import { CenterFocusStrongOutlined, PermIdentityOutlined, ReceiptOutlined, LocalPoliceOutlined, SecurityOutlined, AccountBalanceOutlined } from '@mui/icons-material';
import { AccountGroupOutline } from 'mdi-material-ui';
import BreadcrumbHeader from 'src/components/BreadcrumbHeader';
import { makeStyles } from '@mui/styles';
import type { Theme } from 'src/components/Theme';
import { useFormatter } from 'src/components/i18n';
import { useLocation } from 'react-router-dom';
import useGranted, { VIRTUAL_ORGANIZATION_ADMIN, SETTINGS_SETACCESSES, SETTINGS_SETMARKINGS } from '../../../utils/hooks/useGranted';
import NavToolbarMenu, { MenuEntry } from '../common/menus/NavToolbarMenu';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    paddingBottom: 25,
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
}));

const AccessesMenu: FunctionComponent = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/roles',
      label: 'Roles',
      icon: <SecurityOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/groups',
      label: 'Groups',
      icon: <AccountGroupOutline fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/users',
      label: 'Users',
      icon: <PermIdentityOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/organizations',
      label: 'Organizations',
      icon: <AccountBalanceOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/sessions',
      label: 'Sessions',
      icon: <ReceiptOutlined fontSize="medium" />,
    },
    {
      path: '/dashboard/settings/accesses/policies',
      label: 'Policies',
      icon: <LocalPoliceOutlined fontSize="medium" />,
    },
  ];
  const markingEntries: MenuEntry[] = [
    {
      path: '/dashboard/settings/accesses/marking',
      label: 'Marking definitions',
      icon: <CenterFocusStrongOutlined fontSize="medium" />,
    },
  ];
  const setAccess = useGranted([SETTINGS_SETACCESSES]);
  const setMarkings = useGranted([SETTINGS_SETMARKINGS]);
  const isOrgaAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);
  const menuEntries = [];
  if (setAccess) {
    menuEntries.push(...entries);
  }
  if (setMarkings) {
    menuEntries.push(...markingEntries);
  }
  if (menuEntries.length === 0 && isOrgaAdmin) {
    menuEntries.push(
      ...[
        {
          path: '/dashboard/settings/accesses/organizations',
          label: 'Organizations',
          icon: <AccountBalanceOutlined fontSize="medium" />,
        },
        {
          path: '/dashboard/settings/accesses/users',
          label: 'Users',
          icon: <PermIdentityOutlined fontSize="medium" />,
        },
      ],
    );
  }
  const currentPath = menuEntries.filter(({ path }) => location
    .pathname
    .includes(path))[0]
    .label;
  const isTopLevel = location.pathname
    .replace('?', '')
    .split('/')
    .filter((path) => path !== '')
    .length === 4;
  const path: { text: string, link?: string }[] = [
    { text: t_i18n('Settings') },
    { text: t_i18n('Security'), link: '/dashboard/settings/accesses' },
  ];
  if (!isTopLevel) {
    path.push({
      text: t_i18n(currentPath),
      link: menuEntries.filter(({ label }) => label === currentPath)[0].path,
    });
  }
  return (<>
    <BreadcrumbHeader path={path}>
      {isTopLevel
        ? <div className={ classes.header }>{t_i18n(currentPath)}</div>
        : <></>
      }
    </BreadcrumbHeader>
    <NavToolbarMenu entries={menuEntries} />
  </>);
};

export default AccessesMenu;
