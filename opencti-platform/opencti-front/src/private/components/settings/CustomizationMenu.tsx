import React, { FunctionComponent } from 'react';
import BreadcrumbHeader from 'src/components/BreadcrumbHeader';
import { makeStyles } from '@mui/styles';
import type { Theme } from 'src/components/Theme';
import { useFormatter } from 'src/components/i18n';
import { useLocation } from 'react-router-dom';
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

const CustomizationMenu: FunctionComponent = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/customization/entity_types',
      label: 'Entity types',
    },
    {
      path: '/dashboard/settings/customization/rules',
      label: 'Rules engine',
    },
    {
      path: '/dashboard/settings/customization/notifiers',
      label: 'Notifiers',
    },
    {
      path: '/dashboard/settings/customization/retention',
      label: 'Retention policies',
    },
  ];
  const currentPath = entries.filter(({ path }) => location
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
    { text: t_i18n('Customization') },
  ];
  if (!isTopLevel) {
    path.push({
      text: t_i18n(currentPath),
      link: entries.filter(({ label }) => label === currentPath)[0].path,
    });
  }
  return (<>
    <BreadcrumbHeader path={path}>
      {isTopLevel
        ? <div className={ classes.header }>{t_i18n(currentPath)}</div>
        : <></>
      }
    </BreadcrumbHeader>
    <NavToolbarMenu entries={entries} />
  </>);
};

export default CustomizationMenu;
