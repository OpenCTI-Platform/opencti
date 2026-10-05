import { SOURCE_INTELLIGENCE_MANAGER_ID } from '../sourceIntelligence/sourceIntelligence-types';
import { DEFAULT_SOURCE_INTELLIGENCE_SETTINGS } from '../sourceIntelligence/sourceIntelligence-settings';

export const supportedMimeTypes = [
  'application/pdf',
  'application/json',
  'text/plain',
  'text/markdown',
  'text/csv',
  'text/html',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.oasis.opendocument.text',
];
const defaultManagerConfigurations = [
  {
    manager_id: 'FILE_INDEX_MANAGER',
    manager_running: false,
    manager_setting: {
      accept_mime_types: supportedMimeTypes,
      include_global_files: false,
      entity_types: [],
      max_file_size: 5242880,
    },
  },
  {
    manager_id: SOURCE_INTELLIGENCE_MANAGER_ID,
    manager_running: true,
    manager_setting: DEFAULT_SOURCE_INTELLIGENCE_SETTINGS,
  },
];

export const getDefaultManagerConfiguration = (managerId: string) => {
  const managerConfiguration = defaultManagerConfigurations.find((e) => e.manager_id === managerId);
  return managerConfiguration ? { ...managerConfiguration.manager_setting } : null;
};

export const getAllDefaultManagerConfigurations = () => {
  return [...defaultManagerConfigurations];
};
