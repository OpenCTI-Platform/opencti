import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';
import BreadcrumbHeader from 'src/components/BreadcrumbHeader';
import { useFormatter } from 'src/components/i18n';
import { makeStyles } from '@mui/styles';
import type { Theme } from 'src/components/Theme';
import { useLocation } from 'react-router-dom';

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
import useGranted, { MODULES } from '../../../utils/hooks/useGranted';

const IngestionMenu = () => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const location = useLocation();
  const isConnectorReader = useGranted([MODULES]);
  const entries: MenuEntry[] = [
    {
      path: '/dashboard/data/ingestion/sync',
      label: 'Remote OCTI Streams',
    },
    {
      path: '/dashboard/data/ingestion/taxii',
      label: 'TAXII Feeds',
    },
    {
      path: '/dashboard/data/ingestion/rss',
      label: 'RSS Feeds',
    },
    {
      path: '/dashboard/data/ingestion/csv',
      label: 'CSV Feeds',
    },
  ];
  if (isConnectorReader) {
    entries.push({
      path: '/dashboard/data/ingestion/connectors',
      label: 'Connectors',
    });
  }
  return <NavToolbarMenu entries={entries} />;
  const currentPath = entries.filter(({ path }) => location
    .pathname
    .includes(path))[0]
    .label;
  return (
    <>
      <BreadcrumbHeader
        path={[
          { text: t_i18n('Data') },
          { text: t_i18n('Ingestion') },
        ]}
      >
        <div className={ classes.header }>{t_i18n(currentPath)}</div>
      </BreadcrumbHeader>
      <NavToolbarMenu entries={entries} />
    </>
  );
};

export default IngestionMenu;
