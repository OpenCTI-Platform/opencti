import * as R from 'ramda';
import { getClusterInstances } from './redis';

export const getClusterInformation = async () => {
  const clusterConfig = await getClusterInstances();
  const info = { instances_number: clusterConfig.length };
  const allManagers = clusterConfig.map((i) => i.managers).flat();
  const groupManagersById = R.groupBy((manager) => manager.id, allManagers);
  const modules = Object.entries(groupManagersById).map(([id, managers]) => ({
    id,
    enable: managers.reduce((acc, m) => acc || m.enable, false),
    running: managers.reduce((acc, m) => acc || m.running, false),
    warning: managers.reduce((acc, m) => acc || m.warning, false),
  }));
  return { info, modules };
};

export const isModuleActivated = async (moduleId) => {
  const clusterInfo = await getClusterInformation();
  const module = clusterInfo.modules.find((m) => m.id === moduleId);
  return module ? module.enable : false;
};
