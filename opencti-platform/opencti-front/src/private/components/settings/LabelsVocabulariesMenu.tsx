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

const LabelsVocabulariesMenu: FunctionComponent = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/settings/vocabularies/labels',
      label: 'Labels',
    },
    {
      path: '/dashboard/settings/vocabularies/kill_chain_phases',
      label: 'Kill chain phases',
    },
    {
      path: '/dashboard/settings/vocabularies/fields',
      label: 'Vocabularies',
    },
    {
      path: '/dashboard/settings/vocabularies/status_templates',
      label: 'Status templates',
    },
    {
      path: '/dashboard/settings/vocabularies/case_templates',
      label: 'Case templates',
    },
  ];

  const currentPath = entries.filter(({ path }) => location
    .pathname
    .includes(path))[0]
    .label;
  const lastPath = location.pathname.split('/').slice(-1)[0];
  const isTopLevel = location.pathname
    .replace('?', '')
    .split('/')
    .filter((path) => path !== '')
    .length === 4;
  const path: { text: string, link?: string }[] = [
    { text: t_i18n('Settings') },
    { text: t_i18n('Taxonomies') },
  ];
  let altDisplay;
  if (!isTopLevel) {
    path.push({
      text: t_i18n(currentPath),
      link: entries.filter(({ label }) => label === currentPath)[0].path,
    });
    if (location.pathname.includes('vocabularies/fields')) {
      altDisplay = (<div className={ classes.header }>{lastPath}</div>);
    }
  }
  return (<>
    <BreadcrumbHeader path={path}>
      {isTopLevel
        ? <div className={ classes.header }>{t_i18n(currentPath)}</div>
        : <>{altDisplay}</>
      }
    </BreadcrumbHeader>
    <NavToolbarMenu entries={entries} />
  </>);
};

export default LabelsVocabulariesMenu;
