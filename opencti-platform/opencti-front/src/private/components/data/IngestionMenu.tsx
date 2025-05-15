import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';
import useGranted, { INGESTION, MODULES } from '../../../utils/hooks/useGranted';
import useHelper from '../../../utils/hooks/useHelper';

const IngestionMenu = () => {
  const isConnectorReader = useGranted([MODULES]);
  const isGrantedIngestion = useGranted([INGESTION]);
  const { isFeatureEnable } = useHelper();
  const isJsonMapperEnable = isFeatureEnable('JSON_MAPPER');
  const settingsEntries: MenuEntry[] = [
    {
      path: '/dashboard/data/ingestion/sync',
      label: 'OpenCTI Streams',
    },
    {
      path: '/dashboard/data/ingestion/taxii',
      label: 'TAXII Feeds',
    },
    {
      path: '/dashboard/data/ingestion/collection',
      label: 'TAXII Push',
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
  if (isJsonMapperEnable) {
    settingsEntries.push({
      path: '/dashboard/data/ingestion/json',
      label: 'JSON Feeds',
      isEE: true,
    });
  }
  const entries: MenuEntry[] = isGrantedIngestion ? [...settingsEntries] : [];
  if (isConnectorReader) {
    entries.unshift({
      path: '/dashboard/data/ingestion/connectors',
      label: 'Connectors',
    });
  }
  return <NavToolbarMenu entries={entries} />;
};

export default IngestionMenu;
