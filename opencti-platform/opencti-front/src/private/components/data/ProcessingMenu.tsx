import React from 'react';
import NavToolbarMenu, { MenuEntry } from '@components/common/menus/NavToolbarMenu';
import useGranted, { AUTOMATION_AUTMANAGE, CSVMAPPERS, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';

const ProcessingMenu = () => {
  const isAutomationManager = useGranted([AUTOMATION_AUTMANAGE]);
  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]);
  const isMapperUpdater = useGranted([CSVMAPPERS]);
  const entries: MenuEntry[] = [];
  if (isAutomationManager) {
    entries.push({
      path: '/dashboard/data/processing/automation',
      label: 'Automation',
      isEE: true,
    });
  }
  if (isKnowledgeUpdater) {
    entries.push({
      path: '/dashboard/data/processing/tasks',
      label: 'Tasks',
    });
  }
  if (isMapperUpdater) {
    entries.push(
      {
        path: '/dashboard/data/processing/csv_mapper',
        label: 'CSV Mappers',
      },
      {
        path: '/dashboard/data/processing/json_mapper',
        label: 'JSON Mappers',
      },
    );
  }
  return <NavToolbarMenu entries={entries} />;
};

export default ProcessingMenu;
