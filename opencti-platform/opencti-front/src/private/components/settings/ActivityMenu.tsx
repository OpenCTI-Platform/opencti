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

const ActivityMenu: FunctionComponent = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/activity/audit',
      label: 'Events',
    },
    {
      path: '/dashboard/settings/activity/configuration',
      label: 'Configuration',
    },
    {
      path: '/dashboard/settings/activity/alerting',
      label: 'Alerting',
    },
  ];

  const currentPath = entries.filter(({ path }) => location
    .pathname
    .includes(path))[0]
    .label;
  return (<>
    <BreadcrumbHeader path={[
      { text: t_i18n('Settings') },
      { text: t_i18n('Activity') },
    ]}
    >
      <div className={ classes.header }>{t_i18n(currentPath)}</div>
    </BreadcrumbHeader>
    <NavToolbarMenu entries={entries} />
  </>);
};

export default ActivityMenu;
