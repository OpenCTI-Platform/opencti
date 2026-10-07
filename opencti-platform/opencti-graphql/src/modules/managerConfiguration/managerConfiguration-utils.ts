import { DEFAULT_PROVENANCE_BACKFILL_STATE, PROVENANCE_BACKFILL_MANAGER_ID } from '../provenance/provenance-types';

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
    manager_id: PROVENANCE_BACKFILL_MANAGER_ID,
    manager_running: false,
    manager_setting: { ...DEFAULT_PROVENANCE_BACKFILL_STATE },
  },
];

export const getDefaultManagerConfiguration = (managerId: string) => {
  const managerConfiguration = defaultManagerConfigurations.find((e) => e.manager_id === managerId);
  return managerConfiguration ? { ...managerConfiguration.manager_setting } : null;
};

export const getAllDefaultManagerConfigurations = () => {
  return [...defaultManagerConfigurations];
};
