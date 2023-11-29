const defaultManagerConfigurations = [
  {
    manager_id: 'FILE_INDEX_MANAGER',
    manager_running: false,
    manager_setting: {
      accept_mime_types: ['application/pdf', 'text/plain', 'text/csv', 'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'text/html'],
      include_global_files: false,
      max_file_size: 5242880,
    }
  }
];

export const getDefaultManagerConfiguration = (managerId: string) => {
  const managerConfiguration = defaultManagerConfigurations.find((e) => e.manager_id === managerId);
  return managerConfiguration ? { ...managerConfiguration.manager_setting } : null;
};

export const getAllDefaultManagerConfigurations = () => {
  return [...defaultManagerConfigurations];
};
