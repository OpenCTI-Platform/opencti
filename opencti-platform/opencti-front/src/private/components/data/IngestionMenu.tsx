import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';

const IngestionMenu = () => {
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
      path: '/dashboard/data/ingestion/csv_mapper',
      label: 'CSV Mappers',
    },
  ];

  return <NavToolbarMenu entries={entries} />;
};

export default IngestionMenu;
